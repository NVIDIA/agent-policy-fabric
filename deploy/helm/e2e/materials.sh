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
# shellcheck source=../../scripts/apf-materials.sh
source "${APF_DIR}/deploy/scripts/apf-materials.sh"

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
  ensure_http_token "${HTTP_TOKEN}"
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
  make_cert "${TLS_CRT}" "${TLS_KEY}" "${APF_SERVICE_HOST}" \
    "DNS:${APF_SERVICE_HOST}" "DNS:${APF_FULLNAME}.${APF_NS}.svc" "DNS:${APF_FULLNAME}.${APF_NS}" "DNS:${APF_FULLNAME}"
  if [[ "${LOCAL_ONLY}" == 1 ]]; then
    ok "local-only materials complete in ${E2E_WORK} (cluster steps skipped)"
    return
  fi
  require_cmd kubectl
  read_openshell_jwt
  # One trust profile per listener: sandbox admission verifies the interceptor
  # audience, egress request policy the middleware audience.
  write_trust "${TRUST_INTERCEPTOR}" "${OPENSHELL_JWT_ISSUER}" "${INTERCEPTOR_AUDIENCE}" "${JWT_KID_FILE}" "${JWT_PUB}"
  write_trust "${TRUST_MIDDLEWARE}" "${OPENSHELL_JWT_ISSUER}" "${MIDDLEWARE_AUDIENCE}" "${JWT_KID_FILE}" "${JWT_PUB}"
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
