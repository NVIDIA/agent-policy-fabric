#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# materials.sh [all]        build everything the charts need and apply it to the cluster
# materials.sh bundle v1|v2 re-create ConfigMap apf-bundle from that bundle revision
#
# Outputs land in E2E_WORK: signed bundle tarballs, the APF serving certificate,
# the OpenShell JWT public key and kid, the trust profiles, and the HTTP token.
# Every step is safe to rerun. E2E_MATERIALS_LOCAL_ONLY=1 runs only the steps
# that need no cluster (compile check, bundle staging and signing, certificate).

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

LOCAL_ONLY="${E2E_MATERIALS_LOCAL_ONLY:-0}"
TLS_DIR="${E2E_WORK}/tls"
TLS_CRT="${TLS_DIR}/apf.crt"
TLS_KEY="${TLS_DIR}/apf.key"
JWT_PUB="${E2E_WORK}/openshell-jwt-public.pem"
JWT_KID_FILE="${E2E_WORK}/openshell-jwt-kid"
TRUST_INTERCEPTOR="${E2E_WORK}/trust-interceptor.toml"
TRUST_MIDDLEWARE="${E2E_WORK}/trust-middleware.toml"
HTTP_TOKEN="${E2E_WORK}/http-bearer-token"
PIP_RENDERED="${E2E_WORK}/pips.yaml"

mkdir -p "${E2E_WORK}" "${TLS_DIR}"

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
# with the dev key, and packs E2E_WORK/bundle-<rev>.tar.gz with root dir bundle/.
stage_bundle() {
  local rev="$1" stage dir template name
  stage="${E2E_WORK}/bundle-${rev}"
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
  name="${E2E_WORK}/bundle-${rev}.tar.gz"
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
# the trust root the chart receives, the same check the policy service runs at
# startup, and records the digest for smoke.sh.
verify_bundle() {
  local rev="$1" manifest="$2" out
  out="$("${APF_COMPILE}" compile --verify-only \
    --bundle-path "${manifest}" \
    --trust-root-dir "${DEV_KEYS_DIR}" \
    --key-id "${SIGNING_KEY_ID}" 2>&1)" || fail "offline verification of bundle ${rev} failed: ${out}"
  echo "  ${out}"
  shasum -a 256 "${manifest}" | cut -d' ' -f1 >"${E2E_WORK}/bundle-${rev}.digest"
}

read_openshell_jwt() {
  local pem kid
  if ! kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" >/dev/null 2>&1; then
    fail "Secret ${OPENSHELL_NS}/${OPENSHELL_JWT_SECRET} not found; install the OpenShell release first (up.sh does this before materials.sh)"
  fi
  pem="$(kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" -o 'jsonpath={.data.public\.pem}' | base64 --decode)"
  kid="$(kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" -o 'jsonpath={.data.kid}' | base64 --decode | tr -d '\r\n')"
  [[ "${pem}" == *"BEGIN PUBLIC KEY"* ]] || fail "Secret ${OPENSHELL_JWT_SECRET} key public.pem is not a PEM public key"
  [[ -n "${kid}" ]] || fail "Secret ${OPENSHELL_JWT_SECRET} key kid is empty"
  printf '%s\n' "${pem}" >"${JWT_PUB}"
  printf '%s\n' "${kid}" >"${JWT_KID_FILE}"
  ok "OpenShell JWT public key (kid ${kid}) read from ${OPENSHELL_NS}/${OPENSHELL_JWT_SECRET}"
}

make_cert() {
  local cfg="${TLS_DIR}/openssl.cnf"
  if [[ -f "${TLS_CRT}" && -f "${TLS_KEY}" ]] && openssl x509 -in "${TLS_CRT}" -noout -text | grep -q "DNS:${APF_SERVICE_HOST}"; then
    log "APF serving certificate present: ${TLS_CRT}"
    return
  fi
  cat >"${cfg}" <<CNF
[req]
distinguished_name = dn
x509_extensions = server
prompt = no

[dn]
CN = ${APF_SERVICE_HOST}

[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt

[alt]
DNS.1 = ${APF_SERVICE_HOST}
DNS.2 = ${APF_FULLNAME}.${APF_NS}.svc
DNS.3 = ${APF_FULLNAME}.${APF_NS}
DNS.4 = ${APF_FULLNAME}
CNF
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${TLS_KEY}" -out "${TLS_CRT}" -config "${cfg}" 2>/dev/null
  chmod 0600 "${TLS_KEY}"
  ok "APF serving certificate generated for ${APF_SERVICE_HOST}"
}

# write_trust <out> <audience>
write_trust() {
  local out="$1" audience="$2"
  cat >"${out}" <<TOML
issuer = "${OPENSHELL_JWT_ISSUER}"
audience = "${audience}"
kid = "$(cat "${JWT_KID_FILE}")"
public_key_pem = """
$(cat "${JWT_PUB}")
"""
max_lifetime_secs = 3600
leeway_secs = 60
TOML
}

ensure_http_token() {
  if [[ ! -s "${HTTP_TOKEN}" ]]; then
    openssl rand -hex 32 >"${HTTP_TOKEN}"
    chmod 0600 "${HTTP_TOKEN}"
  fi
}

apply_bundle() {
  local rev="$1" tarball
  tarball="${E2E_WORK}/bundle-${rev}.tar.gz"
  [[ -f "${tarball}" ]] || stage_bundle "${rev}"
  kctl -n "${APF_NS}" create configmap apf-bundle --from-file="bundle.tar.gz=${tarball}" \
    --dry-run=client -o yaml | kctl apply -f -
  ok "ConfigMap ${APF_NS}/apf-bundle holds bundle ${rev}"
}

apply_apf_materials() {
  kctl create namespace "${APF_NS}" --dry-run=client -o yaml | kctl apply -f -
  ensure_http_token
  kctl -n "${APF_NS}" create secret generic apf-runtime \
    --from-file="document-signing.seed=${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" \
    --from-file="token=${HTTP_TOKEN}" \
    --from-file="tls.crt=${TLS_CRT}" \
    --from-file="tls.key=${TLS_KEY}" \
    --from-file="trust.toml=${TRUST_INTERCEPTOR}" \
    --dry-run=client -o yaml | kctl apply -f -
  kctl -n "${APF_NS}" create secret generic apf-egress \
    --from-file="tls.crt=${TLS_CRT}" \
    --from-file="tls.key=${TLS_KEY}" \
    --from-file="trust.toml=${TRUST_MIDDLEWARE}" \
    --dry-run=client -o yaml | kctl apply -f -
  kctl -n "${APF_NS}" create configmap apf-trust \
    --from-file="${SIGNING_KEY_ID}.pub=${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub" \
    --dry-run=client -o yaml | kctl apply -f -
  apply_bundle v1
  kctl -n "${OPENSHELL_NS}" create configmap apf-ca --from-file="ca.crt=${TLS_CRT}" \
    --dry-run=client -o yaml | kctl apply -f -
  ok "Secrets apf-runtime, apf-egress and ConfigMaps apf-trust, apf-bundle (${APF_NS}), apf-ca (${OPENSHELL_NS}) applied"
}

apply_pip_materials() {
  [[ -f "${PIP_CONFIG_SRC}" ]] || fail "PIP_CONFIG_SRC not found: ${PIP_CONFIG_SRC}"
  [[ -f "${PIP_STUB_SRC}" ]] || fail "PIP_STUB_SRC not found: ${PIP_STUB_SRC}"
  # The provider behind the registration runs as a sidecar in the APF pod, so
  # the registration's loopback URLs are used as written.
  cp "${PIP_CONFIG_SRC}" "${PIP_RENDERED}"
  kctl -n "${APF_NS}" create configmap apf-pip --from-file="pips.yaml=${PIP_RENDERED}" \
    --dry-run=client -o yaml | kctl apply -f -
  kctl -n "${APF_NS}" create configmap apf-pip-stub --from-file="stub.py=${PIP_STUB_SRC}" \
    --dry-run=client -o yaml | kctl apply -f -
  ok "ConfigMaps apf-pip and apf-pip-stub applied (provider on 127.0.0.1:${PIP_STUB_PORT}, served by the pip-stub sidecar)"
}

all() {
  require_cmd openssl python3 tar
  [[ -f "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" ]] || fail "signing seed missing: ${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed"
  [[ -f "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub" ]] || fail "trust key missing: ${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub"
  [[ -d "${BUNDLE_SRC}" ]] || fail "BUNDLE_SRC not found: ${BUNDLE_SRC}"
  log "bundle source: ${BUNDLE_SRC}"
  ensure_compile
  stage_bundle v1
  stage_bundle v2
  make_cert
  if [[ "${LOCAL_ONLY}" == 1 ]]; then
    ok "local-only materials complete in ${E2E_WORK} (cluster steps skipped)"
    return
  fi
  require_cmd kubectl
  read_openshell_jwt
  # One trust profile per listener: sandbox admission verifies the interceptor
  # audience, egress request policy the middleware audience.
  write_trust "${TRUST_INTERCEPTOR}" "${INTERCEPTOR_AUDIENCE}"
  write_trust "${TRUST_MIDDLEWARE}" "${MIDDLEWARE_AUDIENCE}"
  ok "trust profiles written (issuer ${OPENSHELL_JWT_ISSUER})"
  apply_apf_materials
  if [[ "${PIP_ENABLED}" == 1 ]]; then
    apply_pip_materials
  else
    log "PIP disabled (PIP_CONFIG_SRC empty); no apf-pip or apf-pip-stub materials"
  fi
}

case "${1:-all}" in
  all) all ;;
  bundle)
    rev="${2:-}"
    [[ "${rev}" == v1 || "${rev}" == v2 ]] || { echo "usage: materials.sh bundle v1|v2" >&2; exit 2; }
    ensure_compile
    stage_bundle "${rev}"
    apply_bundle "${rev}"
    log "the pod does not watch the ConfigMap; run: kubectl --context ${KIND_CONTEXT} -n ${APF_NS} rollout restart deployment/${APF_FULLNAME}"
    ;;
  *) echo "usage: materials.sh [all] | bundle v1|v2" >&2; exit 2 ;;
esac
