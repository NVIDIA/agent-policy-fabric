#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# materials.sh [--openshell]   build everything the stack needs and write it into the volumes
# materials.sh bundle v1|v2    re-sign that bundle revision into E2E_WORK
#
# Outputs land in E2E_WORK: the signed bundle revisions (revision 1 is what
# compose.yaml bind-mounts), the HTTP token, and with --openshell the APF
# serving certificate, the OpenShell extension-JWT key pair, the trust
# profiles and the rendered gateway TOML. Secrets are then written into the
# project's named volumes through throwaway runs of the policy-service image,
# so they land owned by 65532 with owner-only modes on every engine. Every
# step is safe to rerun.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
# shellcheck source=../../scripts/apf-materials.sh
source "${APF_DIR}/deploy/scripts/apf-materials.sh"

TLS_DIR="${E2E_WORK}/tls"
TLS_CRT="${TLS_DIR}/apf.crt"
TLS_KEY="${TLS_DIR}/apf.key"
JWT_DIR="${E2E_WORK}/openshell-jwt"
TRUST_INTERCEPTOR="${E2E_WORK}/trust-interceptor.toml"
TRUST_MIDDLEWARE="${E2E_WORK}/trust-middleware.toml"
HTTP_TOKEN="${E2E_WORK}/http-bearer-token"
SERVICE_IMAGE="apf-policy-service:${APF_IMAGE_TAG}"

mkdir -p "${E2E_WORK}" "${TLS_DIR}"

# run_in_volumes <user> <volume:mountpoint>... -- <sh -c script>: a throwaway
# run of the policy-service image with the named volumes attached, reading
# stdin so a tar stream can be extracted into a volume.
run_in_volumes() {
  local user="$1" mounts=() spec
  shift
  while [[ $# -gt 0 && "$1" != -- ]]; do
    spec="$1"
    mounts+=(-v "$(volume_name "${spec%%:*}"):${spec#*:}")
    shift
  done
  shift
  docker run --rm -i --user "${user}" --entrypoint sh "${mounts[@]}" "${SERVICE_IMAGE}" -c "$1"
}

# The volumes must exist before anything writes into them, and compose must be
# the one that creates them.
create_project() {
  compose up --no-start --quiet-pull >/dev/null 2>&1 || compose up --no-start
  ok "project ${COMPOSE_PROJECT_NAME} created (containers stopped, volumes present)"
}

# Fresh named volumes are root-owned, as the image directories at their mount
# points are; hand them to the service user before the first write.
init_volumes() {
  local spec="apf-run:/run/apf apf-state:/var/lib/apf apf-audit:/var/log/apf/audit apf-secrets:/etc/apf/secrets"
  [[ "${WITH_OPENSHELL}" == 1 ]] && spec+=" apf-openshell:/etc/apf/openshell"
  # shellcheck disable=SC2086
  run_in_volumes 0:0 ${spec} -- '
    set -e
    for d in /run/apf /var/lib/apf /var/log/apf/audit /etc/apf/secrets /etc/apf/openshell; do
      [ -d "$d" ] || continue
      [ "$(stat -c %u "$d")" = 65532 ] || chown 65532:65532 "$d"
    done
    chmod 0700 /etc/apf/secrets
    [ -d /etc/apf/openshell ] && chmod 0755 /etc/apf/openshell || true' </dev/null
  ok "volumes owned by 65532"
}

# The bearer token and the document signing seed, 0400 owned by 65532.
write_secrets() {
  local stage="${E2E_WORK}/secrets-stage"
  ensure_http_token "${HTTP_TOKEN}"
  rm -rf "${stage}"
  mkdir -p "${stage}"
  cp "${HTTP_TOKEN}" "${stage}/http-bearer-token"
  cp "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" "${stage}/document-signing.seed"
  (cd "${stage}" && COPYFILE_DISABLE=1 tar -cf - .) | run_in_volumes 65532:65532 apf-secrets:/etc/apf/secrets -- '
    set -e
    umask 077
    cd /etc/apf/secrets
    rm -f http-bearer-token document-signing.seed
    tar -xf - --no-same-owner --no-same-permissions --warning=no-unknown-keyword
    chmod 0400 http-bearer-token document-signing.seed
    ls -l'
  rm -rf "${stage}"
  ok "secrets written into volume $(volume_name apf-secrets)"
}

# render_gateway_toml: writes the environment-adjusted copy of the committed
# gateway TOML variant that the overlay mounts.
render_gateway_toml() {
  local src="${COMPOSE_DIR}/config/openshell-gateway.${OPENSHELL_COMPUTE_DRIVER}.toml"
  [[ -f "${src}" ]] || fail "no gateway TOML for OPENSHELL_COMPUTE_DRIVER=${OPENSHELL_COMPUTE_DRIVER}: ${src}"
  mkdir -p "$(dirname "${OPENSHELL_GATEWAY_TOML}")"
  sed -E \
    -e "s|^(bind_address[[:space:]]*=[[:space:]]*\"0\.0\.0\.0:)[0-9]+\"|\1${OPENSHELL_PORT}\"|" \
    -e "s|^(health_bind_address[[:space:]]*=[[:space:]]*\"0\.0\.0\.0:)[0-9]+\"|\1${OPENSHELL_HEALTH_PORT}\"|" \
    -e "s|^(gateway_id[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"${OPENSHELL_GATEWAY_ID}\"|" \
    -e "s|^(sandbox_label[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"${OPENSHELL_GATEWAY_ID}\"|" \
    -e "s|(urn:openshell:extension:interceptor:)[^\"]*|\1${OPENSHELL_GATEWAY_ID}|" \
    -e "s|(urn:openshell:extension:middleware:)[^\"]*|\1${OPENSHELL_GATEWAY_ID}|" \
    -e "s|^(grpc_endpoint[[:space:]]*=[[:space:]]*\"https://127\.0\.0\.1:)[0-9]+\"|\1${APF_ADMISSION_PORT}\"|" \
    -e "s|^(grpc_endpoint[[:space:]]*=[[:space:]]*\"https://host\.openshell\.internal:)[0-9]+\"|\1${APF_EGRESS_PORT}\"|" \
    -e "s|^(grpc_endpoint[[:space:]]*=[[:space:]]*\"http://127\.0\.0\.1:)[0-9]+\"|\1${OPENSHELL_PORT}\"|" \
    -e "s|^(default_image[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"${SANDBOX_IMAGE}\"|" \
    -e "s|^(supervisor_image[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"${OPENSHELL_IMAGE_REGISTRY}/supervisor:${OPENSHELL_IMAGE_TAG}\"|" \
    -e "s|^(sandbox_runtime_image[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"${OPENSHELL_IMAGE_REGISTRY}/sandbox:${OPENSHELL_IMAGE_TAG}\"|" \
    "${src}" >"${OPENSHELL_GATEWAY_TOML}"
  ok "gateway TOML rendered: ${OPENSHELL_GATEWAY_TOML} (${OPENSHELL_COMPUTE_DRIVER} driver, gateway id ${OPENSHELL_GATEWAY_ID})"
}

# The OpenShell-facing material: serving certificate, extension-JWT key pair,
# one trust profile per listener, and the rendered gateway TOML.
build_openshell_material() {
  make_cert "${TLS_CRT}" "${TLS_KEY}" localhost DNS:localhost DNS:host.openshell.internal IP:127.0.0.1
  make_openshell_jwt "${JWT_DIR}"
  # One trust profile per listener: sandbox admission verifies the interceptor
  # audience, egress request policy the middleware audience.
  write_trust "${TRUST_INTERCEPTOR}" "${OPENSHELL_JWT_ISSUER}" "${INTERCEPTOR_AUDIENCE}" "${JWT_DIR}/kid" "${JWT_DIR}/public.pem"
  write_trust "${TRUST_MIDDLEWARE}" "${OPENSHELL_JWT_ISSUER}" "${MIDDLEWARE_AUDIENCE}" "${JWT_DIR}/kid" "${JWT_DIR}/public.pem"
  ok "trust profiles written (issuer ${OPENSHELL_JWT_ISSUER})"
  render_gateway_toml
}

# Writes the material into the apf-openshell volume as
# <surface>/{tls.crt,tls.key,trust.toml}, ca.crt and jwt/{signing.pem,public.pem,kid}.
write_openshell_material() {
  local stage="${E2E_WORK}/openshell-stage" surface
  rm -rf "${stage}"
  mkdir -p "${stage}/interceptor" "${stage}/middleware" "${stage}/jwt"
  cp "${TLS_CRT}" "${stage}/ca.crt"
  for surface in interceptor middleware; do
    cp "${TLS_CRT}" "${stage}/${surface}/tls.crt"
    cp "${TLS_KEY}" "${stage}/${surface}/tls.key"
  done
  cp "${TRUST_INTERCEPTOR}" "${stage}/interceptor/trust.toml"
  cp "${TRUST_MIDDLEWARE}" "${stage}/middleware/trust.toml"
  cp "${JWT_DIR}/signing.pem" "${JWT_DIR}/public.pem" "${JWT_DIR}/kid" "${stage}/jwt/"
  (cd "${stage}" && COPYFILE_DISABLE=1 tar -cf - .) | run_in_volumes 65532:65532 apf-openshell:/etc/apf/openshell -- '
    set -e
    umask 077
    cd /etc/apf/openshell
    rm -rf interceptor middleware jwt ca.crt
    tar -xf - --no-same-owner --no-same-permissions --warning=no-unknown-keyword
    chmod 0755 interceptor middleware jwt
    chmod 0400 interceptor/tls.key middleware/tls.key jwt/signing.pem
    chmod 0444 ca.crt interceptor/tls.crt middleware/tls.crt interceptor/trust.toml middleware/trust.toml jwt/public.pem jwt/kid
    ls -lR'
  rm -rf "${stage}"
  ok "OpenShell material written into volume $(volume_name apf-openshell)"
}

write_pip_material() {
  [[ -f "${PIP_CONFIG_SRC}" ]] || fail "PIP_CONFIG_SRC not found: ${PIP_CONFIG_SRC}"
  [[ -f "${PIP_STUB_SRC}" ]] || fail "PIP_STUB_SRC not found: ${PIP_STUB_SRC}"
  # The provider behind the registration runs in the pod namespace, so the
  # registration's loopback URLs are used as written.
  cp "${PIP_CONFIG_SRC}" "${PIP_CONFIG}"
  ok "provider registration staged: ${PIP_CONFIG} (stub ${PIP_STUB_SRC} on 127.0.0.1:${PIP_STUB_PORT})"
}

all() {
  require_cmd docker openssl python3 tar shasum
  [[ -f "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" ]] || fail "signing seed missing: ${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed"
  [[ -f "${APF_TRUST_ROOT}" ]] || fail "trust root missing: ${APF_TRUST_ROOT}"
  [[ -d "${BUNDLE_SRC}" ]] || fail "BUNDLE_SRC not found: ${BUNDLE_SRC}"
  docker image inspect "${SERVICE_IMAGE}" >/dev/null 2>&1 || fail "image ${SERVICE_IMAGE} not found; build it first (see README.md)"
  log "bundle source: ${BUNDLE_SRC}"
  ensure_compile
  stage_bundle v1
  stage_bundle v2
  [[ "${PIP_ENABLED}" == 1 ]] && write_pip_material
  if [[ "${WITH_OPENSHELL}" == 1 ]]; then
    mkdir -p "${OPENSHELL_STATE_DIR}"
    build_openshell_material
  fi
  create_project
  init_volumes
  write_secrets
  [[ "${WITH_OPENSHELL}" == 1 ]] && write_openshell_material
  ok "materials complete in ${E2E_WORK}"
}

case "${1:-all}" in
  all|--openshell)
    [[ "${1:-}" == --openshell ]] && WITH_OPENSHELL=1
    all
    ;;
  bundle)
    rev="${2:-}"
    [[ "${rev}" == v1 || "${rev}" == v2 ]] || { echo "usage: materials.sh bundle v1|v2" >&2; exit 2; }
    ensure_compile
    stage_bundle "${rev}"
    log "compose.yaml mounts ${APF_BUNDLE_DIR}; point APF_BUNDLE_DIR at ${E2E_WORK}/bundle-${rev}/bundle and run: docker compose up -d policy-service"
    ;;
  *) echo "usage: materials.sh [all|--openshell] | bundle v1|v2" >&2; exit 2 ;;
esac
