# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Material-building functions shared by the verification environments: bundle
# signing and offline verification, serving certificates, OpenShell
# extension-JWT material and trust profiles, and the policy-service HTTP
# token. Nothing here touches a cluster or a container engine; the environment
# lifecycle (e2e/support/compose-stack.sh, e2e/support/kind-stack.sh) delivers
# the outputs.
#
# Source this file. It expects these variables to be set:
#   APF_DIR              repository root
#   APF_COMPILE          path of the apf-compile binary (built when missing)
#   DEV_KEYS_DIR         directory holding <SIGNING_KEY_ID>.seed and .pub
#   SIGNING_KEY_ID       key id of the bundle signing key (apf-dev)
#   BUNDLE_SRC           bundle source: one *.template.yaml plus its members
#   BUNDLE_V2_TRANSFORM  optional executable applied to the staged revision 2
#   APF_E2E_WORK         work directory for every output
# and these helper functions from e2e/support/common.sh; plain fallbacks are
# defined when they are missing:
#   log, ok, fail, require_cmd
#
# Functions provided:
#   ensure_compile                              build apf-compile when absent
#   stage_bundle v1|v2                          stage, sign, verify, pack a revision
#   show_signature <manifest>                   print the signature carrier and sha256
#   verify_bundle <rev> <manifest>              offline verification; writes bundle-<rev>.digest
#   make_cert <crt> <key> <cn> <san>...         self-signed serving certificate (RSA 2048, 365 days)
#   make_openshell_jwt <dir>                    Ed25519 extension-JWT key pair and kid
#   write_trust <out> <issuer> <audience> <kid-file> <public-pem>
#   ensure_http_token <path>                    random bearer token, created once

declare -F log >/dev/null || log() { printf '  %s\n' "$*"; }
declare -F ok >/dev/null || ok() { printf '  ok   %s\n' "$*"; }
declare -F fail >/dev/null || fail() { printf '  FAIL %s\n' "$*" >&2; exit 1; }
declare -F require_cmd >/dev/null || require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || fail "required command not found on PATH: $c"
  done
}

ensure_compile() {
  if [[ -x "${APF_COMPILE}" ]]; then
    log "apf-compile: ${APF_COMPILE}"
    return
  fi
  require_cmd cargo
  log "building apf-compile (cargo build --release -p apf-compile)"
  (cd "${APF_DIR}" && cargo build --release -p apf-compile)
  [[ -x "${APF_COMPILE}" ]] || fail "apf-compile not found after build: ${APF_COMPILE}"
}

bump_revision_v2() {
  python3 - "$1" <<'PY'
import re, sys, pathlib
t = pathlib.Path(sys.argv[1])
t.write_text(re.sub(r"(policy_revision:\s*)\d+", r"\g<1>2", t.read_text()))
PY
}

# stage_bundle v1|v2: copies BUNDLE_SRC, applies the revision transform, signs
# with the dev key, and packs APF_E2E_WORK/bundle-<rev>.tar.gz with root dir bundle/.
stage_bundle() {
  local rev="$1" stage dir template name
  stage="${APF_E2E_WORK}/bundle-${rev}"
  dir="${stage}/bundle"
  rm -rf "${stage}"
  mkdir -p "${dir}"
  cp -R "${BUNDLE_SRC}/." "${dir}/"
  find "${dir}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  # Previously signed artifacts at the bundle root are not members; drop them.
  find "${dir}" -maxdepth 1 -type f -name '*.yaml' ! -name '*.template.yaml' -delete
  template="$(find "${dir}" -maxdepth 1 -type f -name '*.template.yaml' | head -n 1)"
  [[ -n "${template}" ]] || fail "no *.template.yaml in ${BUNDLE_SRC}"
  if [[ "${rev}" == v2 ]]; then
    bump_revision_v2 "${template}"
    if [[ -n "${BUNDLE_V2_TRANSFORM}" ]]; then
      [[ -x "${BUNDLE_V2_TRANSFORM}" ]] || fail "BUNDLE_V2_TRANSFORM is not executable: ${BUNDLE_V2_TRANSFORM}"
      "${BUNDLE_V2_TRANSFORM}" "${dir}"
    fi
  fi
  # genfixture hashes every member, fills the sha256 placeholders in the
  # template, and signs the document with the Ed25519 seed; it prints one
  # line per member digest.
  "${APF_COMPILE}" genfixture \
    --template "${template}" \
    --base-dir "${dir}" \
    --key "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" \
    --keyid "${SIGNING_KEY_ID}" \
    --out "${dir}/manifest.yaml"
  rm -f "${template}"
  show_signature "${dir}/manifest.yaml"
  verify_bundle "${rev}" "${dir}/manifest.yaml"
  name="${APF_E2E_WORK}/bundle-${rev}.tar.gz"
  rm -f "${name}"
  (cd "${stage}" && COPYFILE_DISABLE=1 tar -czf "${name}" bundle)
  ok "bundle ${rev} signed and packed: ${name}"
}

# show_signature <manifest>: prints the signature carrier appended to the
# signed document (schema, algorithm, key id) and the document's sha256, which
# is the digest the policy service logs when it verifies the bundle.
show_signature() {
  local manifest="$1"
  echo "  signature carrier:"
  grep -E '^(schema|alg|keyid):' "${manifest}" | sed 's/^/    /'
  echo "    document sha256: $(shasum -a 256 "${manifest}" | cut -d' ' -f1)"
}

# verify_bundle <rev> <manifest>: verifies the signed document offline against
# the trust root the deployment receives, the same check the policy service
# runs at startup, and records the digest for the smoke checks.
verify_bundle() {
  local rev="$1" manifest="$2" out
  out="$("${APF_COMPILE}" compile --verify-only \
    --bundle-path "${manifest}" \
    --trust-root-dir "${DEV_KEYS_DIR}" \
    --key-id "${SIGNING_KEY_ID}" 2>&1)" || fail "offline verification of bundle ${rev} failed: ${out}"
  echo "  ${out}"
  shasum -a 256 "${manifest}" | cut -d' ' -f1 >"${APF_E2E_WORK}/bundle-${rev}.digest"
}

# make_cert <crt> <key> <cn> <san>...: writes a self-signed server certificate
# whose subjectAltName lists every <san> (DNS:name or IP:address). An existing
# certificate that already carries all of them is kept.
make_cert() {
  local crt="$1" key="$2" cn="$3"
  shift 3
  local cfg="${crt%/*}/openssl.cnf" san text alt="" n=0
  if [[ -f "${crt}" && -f "${key}" ]]; then
    text="$(openssl x509 -in "${crt}" -noout -text)"
    local present=1
    for san in "$@"; do
      case "${san}" in
        IP:*) grep -q "IP Address:${san#IP:}" <<<"${text}" || present=0 ;;
        *) grep -q "${san}" <<<"${text}" || present=0 ;;
      esac
    done
    if [[ "${present}" == 1 ]]; then
      log "serving certificate present: ${crt}"
      return
    fi
  fi
  mkdir -p "${crt%/*}" "${key%/*}"
  for san in "$@"; do
    n=$((n + 1))
    alt+="${san%%:*}.${n} = ${san#*:}"$'\n'
  done
  cat >"${cfg}" <<CNF
[req]
distinguished_name = dn
x509_extensions = server
prompt = no

[dn]
CN = ${cn}

[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt

[alt]
${alt}
CNF
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${key}" -out "${crt}" -config "${cfg}" 2>/dev/null
  chmod 0600 "${key}"
  ok "serving certificate generated for ${cn} ($*)"
}

# make_openshell_jwt <dir>: writes the OpenShell extension-JWT material an
# OpenShell gateway signs with: signing.pem (Ed25519, PKCS#8), public.pem
# (SPKI) and kid (one line, derived from the public key). Kept when present.
make_openshell_jwt() {
  local dir="$1"
  if [[ -s "${dir}/signing.pem" && -s "${dir}/public.pem" && -s "${dir}/kid" ]]; then
    log "OpenShell JWT key pair present: ${dir} (kid $(cat "${dir}/kid"))"
    return
  fi
  mkdir -p "${dir}"
  openssl genpkey -algorithm ed25519 -out "${dir}/signing.pem" 2>/dev/null
  chmod 0600 "${dir}/signing.pem"
  openssl pkey -in "${dir}/signing.pem" -pubout -out "${dir}/public.pem" 2>/dev/null
  printf 'openshell-%s\n' "$(openssl pkey -pubin -in "${dir}/public.pem" -outform DER 2>/dev/null | shasum -a 256 | cut -c1-16)" >"${dir}/kid"
  ok "OpenShell JWT key pair generated in ${dir} (kid $(cat "${dir}/kid"))"
}

# write_trust <out> <issuer> <audience> <kid-file> <public-pem>: renders the
# trust profile a policy-gateway listener verifies OpenShell extension JWTs
# against. One profile per listener, each with its own audience.
write_trust() {
  local out="$1" issuer="$2" audience="$3" kid_file="$4" pub="$5"
  cat >"${out}" <<TOML
issuer = "${issuer}"
audience = "${audience}"
kid = "$(tr -d '\r\n' <"${kid_file}")"
public_key_pem = """
$(cat "${pub}")
"""
max_lifetime_secs = 3600
leeway_secs = 60
TOML
}

# ensure_http_token <path>: creates the policy-service bearer token once.
ensure_http_token() {
  local path="$1"
  if [[ ! -s "${path}" ]]; then
    mkdir -p "${path%/*}"
    openssl rand -hex 32 >"${path}"
    chmod 0600 "${path}"
  fi
}
