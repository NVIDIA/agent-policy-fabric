# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# OpenShell helpers shared by both environments: the CLI that matches the
# gateway under test (lookup, verified download), the OpenShell release APF's
# protos are pinned to, the extension-JWT trust profiles, and the CLI call
# suites make through the contract. Sourced after common.sh; the trust
# profiles need write_trust from materials.sh.

# The OpenShell release whose protos the APF binaries were generated from, read
# from the pin in crates/apf-proto/build.rs (the comment after the commit).
openshell_proto_pin() {
  sed -n 's/^const OPENSHELL_COMMIT.*\/\/ *v\{0,1\}\([0-9][0-9.]*\).*/\1/p' \
    "${APF_DIR}/crates/apf-proto/build.rs" 2>/dev/null | head -n 1
}

# The release asset triple for this host.
openshell_release_triple() {
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) echo aarch64-apple-darwin ;;
    Darwin/x86_64) echo x86_64-apple-darwin ;;
    Linux/x86_64) echo x86_64-unknown-linux-musl ;;
    Linux/aarch64|Linux/arm64) echo aarch64-unknown-linux-musl ;;
    *) return 1 ;;
  esac
}

# openshell_cli_resolve: prints the CLI to use. OPENSHELL_CLI set by the
# caller wins, then E2E_WORK/openshell, then `openshell` on PATH; nothing when
# none exists.
openshell_cli_resolve() {
  if [[ -n "${OPENSHELL_CLI:-}" ]]; then
    printf '%s' "${OPENSHELL_CLI}"
    return 0
  fi
  if [[ -x "${E2E_WORK}/openshell" ]]; then
    printf '%s' "${E2E_WORK}/openshell"
    return 0
  fi
  command -v openshell 2>/dev/null || true
}

# openshell_cli_version <cli>: prints the version the binary reports
# (`openshell 0.1.3` -> `0.1.3`).
openshell_cli_version() {
  "$1" --version 2>/dev/null | awk 'NR == 1 { print $2 }'
}

# openshell_cli_download <version> <dest>: downloads the release archive for
# this host, verifies it against the release checksum file and installs the
# binary at <dest>. Fails without touching <dest> when anything is off.
openshell_cli_download() {
  local version="$1" dest="$2" triple asset base tmp
  triple="$(openshell_release_triple)" || { log "no OpenShell release asset for $(uname -s)/$(uname -m)"; return 1; }
  asset="openshell-${triple}.tar.gz"
  base="https://github.com/NVIDIA/OpenShell/releases/download/v${version}"
  mkdir -p "$(dirname "${dest}")"
  tmp="$(mktemp -d "$(dirname "${dest}")/openshell-download.XXXXXX")"
  log "downloading ${base}/${asset}"
  if ! curl -fsSL --retry 2 --connect-timeout 15 -o "${tmp}/${asset}" "${base}/${asset}" \
    || ! curl -fsSL --retry 2 --connect-timeout 15 -o "${tmp}/checksums.txt" "${base}/openshell-checksums-sha256.txt"; then
    rm -rf "${tmp}"
    log "download of ${asset} failed"
    return 1
  fi
  if ! (cd "${tmp}" && grep " ${asset}\$" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1); then
    rm -rf "${tmp}"
    log "${asset} does not match openshell-checksums-sha256.txt"
    return 1
  fi
  if ! tar -xzf "${tmp}/${asset}" -C "${tmp}" openshell; then
    rm -rf "${tmp}"
    log "${asset} does not hold 'openshell' at its root"
    return 1
  fi
  chmod 0755 "${tmp}/openshell"
  mv -f "${tmp}/openshell" "${dest}"
  rm -rf "${tmp}"
}

# openshell_cli_ensure <version>: makes OPENSHELL_CLI a CLI of the given
# version, the version of the gateway under test. A resolved CLI of another
# version is replaced by a verified download into E2E_WORK/openshell, unless
# the caller set OPENSHELL_CLI explicitly, which only warns. Without network
# the manual step is named.
openshell_cli_ensure() {
  local version="$1" cli found
  cli="$(openshell_cli_resolve)"
  if [[ -n "${cli}" ]]; then
    [[ -x "${cli}" || -x "$(command -v "${cli}" 2>/dev/null || true)" ]] || fail "OPENSHELL_CLI is not executable: ${cli}"
    found="$(openshell_cli_version "${cli}")"
    if [[ "${found}" == "${version}" ]]; then
      OPENSHELL_CLI="${cli}"
      log "OpenShell CLI ${found}: ${OPENSHELL_CLI}"
      return 0
    fi
    if [[ -n "${OPENSHELL_CLI:-}" ]]; then
      log "OPENSHELL_CLI ${cli} reports version ${found:-unknown}; the gateway under test is ${version}"
      return 0
    fi
    log "OpenShell CLI at ${cli} reports version ${found:-unknown}; the gateway under test is ${version}"
  fi
  require_cmd curl shasum tar
  if openshell_cli_download "${version}" "${E2E_WORK}/openshell"; then
    OPENSHELL_CLI="${E2E_WORK}/openshell"
    ok "OpenShell CLI ${version} installed at ${OPENSHELL_CLI}"
    return 0
  fi
  fail "OpenShell CLI ${version} is required: download openshell-$(openshell_release_triple || echo '<triple>').tar.gz and openshell-checksums-sha256.txt from https://github.com/NVIDIA/OpenShell/releases/tag/v${version}, check the archive against the checksum file, and unpack 'openshell' to ${E2E_WORK}/openshell (or set OPENSHELL_CLI)"
}

# openshell_trust_profiles <out-dir> <issuer> <gateway-id> <kid-file> <public-pem>:
# writes the two trust profiles the policy-gateway listeners verify OpenShell
# extension JWTs against, one per listener with its own audience: sandbox
# admission verifies the interceptor audience, egress request policy the
# middleware audience.
openshell_trust_profiles() {
  local dir="$1" issuer="$2" gateway_id="$3" kid_file="$4" pub="$5"
  mkdir -p "${dir}"
  write_trust "${dir}/trust-interceptor.toml" "${issuer}" "urn:openshell:extension:interceptor:${gateway_id}" "${kid_file}" "${pub}"
  write_trust "${dir}/trust-middleware.toml" "${issuer}" "urn:openshell:extension:middleware:${gateway_id}" "${kid_file}" "${pub}"
  ok "trust profiles written in ${dir} (issuer ${issuer})"
}

# cli <args...>: the OpenShell CLI against the gateway of the current
# environment, through the contract the wrapper exported.
cli() {
  "${APF_E2E_OPENSHELL_CLI}" --gateway-endpoint "${APF_E2E_GATEWAY_URL}" --gateway-insecure "$@"
}
