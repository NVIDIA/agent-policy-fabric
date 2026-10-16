# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Compose lifecycle, sourced by e2e/with-compose-stack.sh after common.sh,
# env-compose.sh, materials.sh and openshell.sh: preflight, materials and
# their delivery into the project's volumes, start, readiness, teardown.
# Secrets land in the named volumes through throwaway runs of the
# policy-service image (no network, read-only root filesystem, no
# capabilities beyond the ones a step names), so they are owned by the user
# that reads them with owner-only modes on every engine. Every step is safe
# to rerun.

TLS_DIR="${APF_E2E_WORK}/tls"
TLS_CRT="${TLS_DIR}/apf.crt"
TLS_KEY="${TLS_DIR}/apf.key"
JWT_DIR="${APF_E2E_WORK}/openshell-jwt"
TRUST_INTERCEPTOR="${APF_E2E_WORK}/trust-interceptor.toml"
TRUST_MIDDLEWARE="${APF_E2E_WORK}/trust-middleware.toml"
HTTP_TOKEN="${APF_E2E_WORK}/http-bearer-token"
# Present between the materials and the start step when the signed document
# changed since the previous run, so the containers that read it are recreated.
BUNDLE_CHANGED_MARK="${APF_E2E_WORK}/bundle-v1.changed"
BUILD="${BUILD:-0}"

# run_in_volumes <user> <caps> <volume:mountpoint>... -- <sh -c script>: a
# throwaway run of the policy-service image with the named volumes attached
# and nothing else: no network, read-only root filesystem, no privilege
# escalation, every capability dropped except the comma-separated <caps>
# (`-` for none). Reads stdin so a tar stream can be extracted into a volume.
run_in_volumes() {
  local user="$1" caps="$2" mounts=() spec cap
  shift 2
  local opts=(--network none --read-only --cap-drop ALL --security-opt no-new-privileges:true)
  if [[ "${caps}" != - ]]; then
    for cap in ${caps//,/ }; do
      opts+=(--cap-add "${cap}")
    done
  fi
  while [[ $# -gt 0 && "$1" != -- ]]; do
    spec="$1"
    mounts+=(-v "$(volume_name "${spec%%:*}"):${spec#*:}")
    shift
  done
  shift
  docker run --rm -i --user "${user}" --entrypoint sh "${opts[@]}" "${mounts[@]}" "${SERVICE_IMAGE}" -c "$1"
}

# Preflight: the engine, the images, the inputs and, with the OpenShell
# overlay, the CLI, the engine socket and the published ports.
compose_preflight() {
  docker info >/dev/null 2>&1 || fail "container engine not reachable through the docker CLI${DOCKER_HOST:+ (DOCKER_HOST=${DOCKER_HOST})}"
  docker compose version >/dev/null 2>&1 || fail "docker compose v2 is required"
  [[ "${APF_IMAGE_TAG}" != latest ]] || fail "APF_IMAGE_TAG=latest is refused; pin a tag"
  [[ "${OPENSHELL_IMAGE_TAG}" != latest ]] || fail "OPENSHELL_IMAGE_TAG=latest is refused; pin a tag"
  if [[ "${BUILD}" == 1 ]]; then
    log "building ${SERVICE_IMAGE} and ${GATEWAY_IMAGE}"
    compose build policy-service policy-gateway
  fi
  local image
  for image in "${SERVICE_IMAGE}" "${GATEWAY_IMAGE}"; do
    docker image inspect "${image}" >/dev/null 2>&1 || fail "image ${image} not found; build it (e2e/README.md, prerequisites) or pass --build"
  done
  [[ -f "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" ]] || fail "signing seed missing: ${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed"
  [[ -f "${APF_TRUST_ROOT}" ]] || fail "trust root missing: ${APF_TRUST_ROOT}"
  [[ -d "${BUNDLE_SRC}" ]] || fail "BUNDLE_SRC not found: ${BUNDLE_SRC}"
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    [[ -f "${PIP_CONFIG_SRC}" ]] || fail "PIP_CONFIG_SRC not found: ${PIP_CONFIG_SRC}"
    [[ -f "${PIP_STUB_SRC}" ]] || fail "PIP_STUB_SRC not found: ${PIP_STUB_SRC}"
  fi
  if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
    [[ -f "${E2E_DIR}/configs/gateway/openshell-gateway.${OPENSHELL_COMPUTE_DRIVER}.toml" ]] \
      || fail "no gateway TOML for OPENSHELL_COMPUTE_DRIVER=${OPENSHELL_COMPUTE_DRIVER} under e2e/configs/gateway"
    openshell_cli_ensure "${OPENSHELL_IMAGE_TAG}"
    check_container_socket
    require_cmd lsof curl
    check_published_ports
  fi
  ok "preflight passed"
}

# check_container_socket: the socket the OpenShell gateway drives sandboxes
# through, tested where the engine resolves it: inside a running Podman
# machine for the podman driver, on this host otherwise.
check_container_socket() {
  local state=""
  if [[ "${OPENSHELL_COMPUTE_DRIVER}" == podman ]] && command -v podman >/dev/null 2>&1; then
    state="$(podman machine inspect --format '{{.State}}' 2>/dev/null | head -n 1 || true)"
  fi
  if [[ "${state}" == running ]]; then
    podman machine ssh -- test -S "${CONTAINER_SOCKET}" 2>/dev/null \
      || fail "CONTAINER_SOCKET ${CONTAINER_SOCKET} is not a socket inside the Podman machine"
    log "engine socket ${CONTAINER_SOCKET} present inside the Podman machine"
    return 0
  fi
  [[ -S "${CONTAINER_SOCKET}" || -e "${CONTAINER_SOCKET}" ]] || fail "CONTAINER_SOCKET not found: ${CONTAINER_SOCKET}"
}

# check_published_ports: a port the overlay publishes must be free, or held
# by this project's own pod from an earlier run (compose recreates it). A
# container of another project or a host process is reported with the knob
# that moves the publish elsewhere. The container half degrades to the host
# check when the engine does not support the publish filter.
check_published_ports() {
  local port pid cmd holder
  for port in "${OPENSHELL_PORT}" "${OPENSHELL_HEALTH_PORT}" "${APF_EGRESS_PORT}"; do
    holder="$(docker ps --filter "publish=${port}" --format '{{.Names}} {{.Label "com.docker.compose.project"}}' 2>/dev/null | head -n 1 || true)"
    if [[ -n "${holder}" ]]; then
      if [[ "${holder##* }" == "${COMPOSE_PROJECT_NAME}" ]]; then
        log "port ${port} is published by this project's ${holder%% *}; compose recreates it"
        continue
      fi
      fail "port 127.0.0.1:${port} is published by container ${holder%% *} (project '${holder##* }'); stop it or set OPENSHELL_PORT/OPENSHELL_HEALTH_PORT/APF_EGRESS_PORT"
    fi
    for pid in $(lsof -nP -tiTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true); do
      cmd="$(ps -o command= -p "${pid}" 2>/dev/null || true)"
      case "${cmd}" in
        *com.docker.backend*|*docker-proxy*|*vpnkit*) continue ;;
      esac
      fail "port ${port} is held by host process ${pid} (${cmd:0:80}); stop it or set OPENSHELL_PORT/OPENSHELL_HEALTH_PORT/APF_EGRESS_PORT"
    done
  done
}

# The volumes must exist before anything writes into them, and compose must be
# the one that creates them.
create_project() {
  compose up --no-start --quiet-pull >/dev/null 2>&1 || compose up --no-start
  ok "project ${COMPOSE_PROJECT_NAME} created (containers stopped, volumes present)"
}

# Fresh named volumes are root-owned, as the image directories at their mount
# points are; hand the ones the APF containers use to the service user before
# the first write. The openshell-jwt volume stays root-owned: the OpenShell
# gateway reads it as root. Changing owners and then modes of directories
# that no longer belong to root takes CHOWN, FOWNER and DAC_OVERRIDE.
init_volumes() {
  local spec="apf-run:/run/apf apf-state:/var/lib/apf apf-audit:/var/log/apf/audit apf-secrets:/etc/apf/secrets"
  [[ "${APF_E2E_OPENSHELL}" == 1 ]] && spec+=" apf-openshell:/etc/apf/openshell"
  # shellcheck disable=SC2086
  run_in_volumes 0:0 CHOWN,FOWNER,DAC_OVERRIDE ${spec} -- '
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
  local stage="${APF_E2E_WORK}/secrets-stage"
  ensure_http_token "${HTTP_TOKEN}"
  rm -rf "${stage}"
  mkdir -p "${stage}"
  cp "${HTTP_TOKEN}" "${stage}/http-bearer-token"
  cp "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" "${stage}/document-signing.seed"
  (cd "${stage}" && COPYFILE_DISABLE=1 tar -cf - .) | run_in_volumes 65532:65532 - apf-secrets:/etc/apf/secrets -- '
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
  local src="${E2E_DIR}/configs/gateway/openshell-gateway.${OPENSHELL_COMPUTE_DRIVER}.toml"
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
  openshell_trust_profiles "${APF_E2E_WORK}" "${OPENSHELL_JWT_ISSUER}" "${OPENSHELL_GATEWAY_ID}" "${JWT_DIR}/kid" "${JWT_DIR}/public.pem"
  render_gateway_toml
}

# Writes the material into two volumes, one per party, so neither holds the
# other's private key: apf-openshell, mounted by the policy gateway, gets
# <listener>/{tls.crt,tls.key,trust.toml} and ca.crt owned by 65532;
# openshell-jwt, mounted by the OpenShell gateway, gets
# jwt/{signing.pem,public.pem,kid} and ca.crt owned by root, the gateway's
# user.
write_openshell_material() {
  local stage="${APF_E2E_WORK}/openshell-stage" surface
  rm -rf "${stage}"
  mkdir -p "${stage}/apf/interceptor" "${stage}/apf/middleware" "${stage}/openshell/jwt"
  cp "${TLS_CRT}" "${stage}/apf/ca.crt"
  cp "${TLS_CRT}" "${stage}/openshell/ca.crt"
  for surface in interceptor middleware; do
    cp "${TLS_CRT}" "${stage}/apf/${surface}/tls.crt"
    cp "${TLS_KEY}" "${stage}/apf/${surface}/tls.key"
  done
  cp "${TRUST_INTERCEPTOR}" "${stage}/apf/interceptor/trust.toml"
  cp "${TRUST_MIDDLEWARE}" "${stage}/apf/middleware/trust.toml"
  cp "${JWT_DIR}/signing.pem" "${JWT_DIR}/public.pem" "${JWT_DIR}/kid" "${stage}/openshell/jwt/"
  (cd "${stage}/apf" && COPYFILE_DISABLE=1 tar -cf - .) | run_in_volumes 65532:65532 - apf-openshell:/etc/apf/openshell -- '
    set -e
    umask 077
    cd /etc/apf/openshell
    rm -rf interceptor middleware jwt ca.crt
    tar -xf - --no-same-owner --no-same-permissions --warning=no-unknown-keyword
    chmod 0755 interceptor middleware
    chmod 0400 interceptor/tls.key middleware/tls.key
    chmod 0444 ca.crt interceptor/tls.crt middleware/tls.crt interceptor/trust.toml middleware/trust.toml
    ls -lR'
  (cd "${stage}/openshell" && COPYFILE_DISABLE=1 tar -cf - .) | run_in_volumes 0:0 - openshell-jwt:/etc/openshell-extensions/apf -- '
    set -e
    umask 077
    cd /etc/openshell-extensions/apf
    rm -rf jwt ca.crt
    tar -xf - --no-same-owner --no-same-permissions --warning=no-unknown-keyword
    chmod 0755 jwt
    chmod 0400 jwt/signing.pem
    chmod 0444 ca.crt jwt/public.pem jwt/kid
    ls -lR'
  rm -rf "${stage}"
  ok "OpenShell material written: listener keys and trust profiles into volume $(volume_name apf-openshell), extension-JWT key pair into volume $(volume_name openshell-jwt)"
}

write_pip_material() {
  [[ -f "${PIP_CONFIG_SRC}" ]] || fail "PIP_CONFIG_SRC not found: ${PIP_CONFIG_SRC}"
  [[ -f "${PIP_STUB_SRC}" ]] || fail "PIP_STUB_SRC not found: ${PIP_STUB_SRC}"
  # The provider behind the registration runs in the pod namespace, so the
  # registration's loopback URLs are used as written.
  mkdir -p "$(dirname "${PIP_CONFIG}")"
  cp "${PIP_CONFIG_SRC}" "${PIP_CONFIG}"
  ok "provider registration staged: ${PIP_CONFIG} (stub ${PIP_STUB_SRC} on 127.0.0.1:${PIP_STUB_PORT})"
}

# Materials: both signed bundle revisions, the provider registration, the
# OpenShell material, then the project and its volumes.
compose_materials() {
  require_cmd docker openssl python3 tar shasum
  mkdir -p "${APF_E2E_WORK}" "${TLS_DIR}"
  log "bundle source: ${BUNDLE_SRC}"
  ensure_compile
  local previous=""
  [[ -f "${APF_E2E_WORK}/bundle-v1.digest" ]] && previous="$(cat "${APF_E2E_WORK}/bundle-v1.digest")"
  stage_bundle v1
  stage_bundle v2
  rm -f "${BUNDLE_CHANGED_MARK}"
  if [[ -n "${previous}" && "${previous}" != "$(cat "${APF_E2E_WORK}/bundle-v1.digest")" ]]; then
    log "signed document changed since the previous run; the containers that read it are recreated"
    : >"${BUNDLE_CHANGED_MARK}"
  fi
  [[ "${APF_E2E_PIP}" == 1 ]] && write_pip_material
  if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
    mkdir -p "${OPENSHELL_STATE_DIR}"
    build_openshell_material
  fi
  create_project
  init_volumes
  write_secrets
  [[ "${APF_E2E_OPENSHELL}" == 1 ]] && write_openshell_material
  ok "materials complete in ${APF_E2E_WORK}"
}

# Start: the APF containers first; the OpenShell gateway is recreated once
# the policy gateway is healthy because it reads its TOML at startup and the
# TOML is rendered from the environment on every run.
compose_up() {
  compose up -d --remove-orphans pod policy-service policy-gateway
  if [[ -f "${BUNDLE_CHANGED_MARK}" ]]; then
    compose up -d --no-deps --force-recreate policy-service policy-gateway
    rm -f "${BUNDLE_CHANGED_MARK}"
  fi
  if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
    wait_until 120 apf_e2e_ready policy-gateway || fail "policy-gateway did not become healthy"
    compose up -d --no-deps --force-recreate openshell-gateway
  fi
  compose ps
}

openshell_gateway_ready_once() { curl -fsS -o /dev/null "http://127.0.0.1:${OPENSHELL_HEALTH_PORT}/readyz" 2>/dev/null; }

# Ready: every container of the run is running and healthy, and the OpenShell
# gateway answers /readyz, which it does only after Describe succeeded on
# every registered extension.
compose_ready() {
  local c components="pod policy-service policy-gateway"
  [[ "${APF_E2E_PIP}" == 1 ]] && components+=" pip-stub"
  [[ "${APF_E2E_OPENSHELL}" == 1 ]] && components+=" openshell-gateway"
  for c in ${components}; do
    wait_until 120 apf_e2e_ready "${c}" || fail "${c} is not running and healthy"
    log "${c}: ready"
  done
  if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
    wait_until 180 openshell_gateway_ready_once || fail "OpenShell gateway not ready at http://127.0.0.1:${OPENSHELL_HEALTH_PORT}/readyz"
    log "openshell-gateway: /readyz answered"
  fi
  compose ps
}

# The gateway, addressed the way the suites address it.
gateway_cli() {
  "$1" --gateway-endpoint "http://127.0.0.1:${OPENSHELL_PORT}" --gateway-insecure "${@:2}"
}
gateway_sandbox_names() { gateway_cli "$1" sandbox list --names 2>/dev/null; }
gateway_lists_no_sandbox() { [[ -z "$(gateway_sandbox_names "$1" || true)" ]]; }

# compose_delete_sandboxes: while the OpenShell gateway runs, deletes every
# sandbox it holds through the CLI and waits until it lists none. The gateway
# is this run's fixture, so everything it holds is this run's; going through
# it works the same on every compute driver.
compose_delete_sandboxes() {
  local cli names name
  apf_e2e_ready openshell-gateway || { log "openshell-gateway is not running; no sandbox deletion through the gateway"; return 0; }
  cli="$(openshell_cli_resolve)"
  [[ -n "${cli}" && -x "${cli}" ]] || { log "no OpenShell CLI resolved; no sandbox deletion through the gateway"; return 0; }
  names="$(gateway_sandbox_names "${cli}" || true)"
  [[ -n "${names}" ]] || { log "the gateway lists no sandbox"; return 0; }
  for name in ${names}; do
    if gateway_cli "${cli}" sandbox delete "${name}" >/dev/null 2>&1; then
      ok "sandbox ${name} deleted through the gateway"
    else
      log "sandbox ${name}: delete through the gateway failed"
    fi
  done
  wait_until 60 gateway_lists_no_sandbox "${cli}" || log "the gateway still lists sandboxes"
}

# Sandboxes are containers and volumes the OpenShell gateway created outside
# compose. The Docker driver labels them with the namespace the rendered TOML
# sets to the gateway id (`sandbox_label`), so this run's are swept by label
# once the gateway is stopped. The Podman driver has no such setting and
# labels them with the request namespace, which other gateways on the engine
# share, so for it the deletion through the gateway is the only removal. The
# openshell-docker network carries no namespace label and is shared with
# other gateways, so it stays.
compose_sweep_sandboxes() {
  if [[ "${OPENSHELL_COMPUTE_DRIVER}" != docker ]]; then
    log "no label sweep with the ${OPENSHELL_COMPUTE_DRIVER} driver: its sandbox label is the request namespace, not the gateway id"
    return 0
  fi
  local filters=(--filter "label=openshell.ai/managed-by=openshell" --filter "label=openshell.ai/sandbox-namespace=${OPENSHELL_GATEWAY_ID}")
  local ids
  ids="$(docker ps -a -q "${filters[@]}" 2>/dev/null || true)"
  if [[ -n "${ids}" ]]; then
    # shellcheck disable=SC2086
    docker rm -f ${ids} >/dev/null
    ok "removed $(wc -w <<<"${ids}" | tr -d ' ') sandbox container(s) of namespace ${OPENSHELL_GATEWAY_ID}"
  fi
  ids="$(docker volume ls -q "${filters[@]}" 2>/dev/null || true)"
  if [[ -n "${ids}" ]]; then
    # shellcheck disable=SC2086
    docker volume rm ${ids} >/dev/null
    ok "removed $(wc -w <<<"${ids}" | tr -d ' ') sandbox volume(s) of namespace ${OPENSHELL_GATEWAY_ID}"
  fi
}

# The gateway runs as root and owns the files in its state directory; a root
# throwaway run empties it where the host user cannot. Only a directory under
# the harness work root is touched: OPENSHELL_STATE_DIR is a knob, and a
# directory elsewhere may be another gateway's.
compose_remove_state_dir() {
  [[ -d "${OPENSHELL_STATE_DIR}" ]] || return 0
  case "${OPENSHELL_STATE_DIR}" in
    "${E2E_WORK}"/*) ;;
    *) log "state directory ${OPENSHELL_STATE_DIR} is outside ${E2E_WORK} and is left in place"; return 0 ;;
  esac
  if docker image inspect "${SERVICE_IMAGE}" >/dev/null 2>&1; then
    docker run --rm --user 0:0 --entrypoint sh --network none --read-only \
      --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add FOWNER --security-opt no-new-privileges:true \
      -v "${OPENSHELL_STATE_DIR}:/state" "${SERVICE_IMAGE}" \
      -c 'find /state -mindepth 1 -delete' >/dev/null 2>&1 || true
  fi
  if rm -rf "${OPENSHELL_STATE_DIR}" 2>/dev/null; then
    ok "removed ${OPENSHELL_STATE_DIR}"
  else
    log "could not remove ${OPENSHELL_STATE_DIR}; remove it with elevated privileges"
  fi
}

# compose_down [volumes]: deletes the sandboxes through the OpenShell gateway
# while it runs, stops the gateway so it cannot recreate what the sweep
# removes, sweeps this run's sandbox containers and volumes by label (Docker
# driver), then takes the project down. `volumes` also removes the named
# volumes (anti-rollback counter, secrets, OpenShell material) and the
# OpenShell state directory.
compose_down() {
  local args=(down --remove-orphans)
  if [[ -n "$(compose_container openshell-gateway)" ]]; then
    compose_delete_sandboxes
    COMPOSE_FILES_SCOPE=all compose stop openshell-gateway >/dev/null 2>&1 || true
  fi
  compose_sweep_sandboxes
  [[ "${1:-}" == volumes ]] && args+=(--volumes)
  COMPOSE_FILES_SCOPE=all compose "${args[@]}"
  ok "project ${COMPOSE_PROJECT_NAME} down"
  [[ "${1:-}" == volumes ]] && compose_remove_state_dir
  return 0
}

# compose_detect_running: for --existing. Fails unless the project runs, and
# sets the lanes from the containers that exist.
compose_detect_running() {
  local running
  running="$(docker ps -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" 2>/dev/null | wc -l | tr -d ' ')"
  [[ "${running}" -gt 0 ]] || fail "no running container of project ${COMPOSE_PROJECT_NAME}; bring the stack up first"
  APF_E2E_OPENSHELL=0
  [[ -n "$(compose_container openshell-gateway)" ]] && APF_E2E_OPENSHELL=1
  APF_E2E_PIP=0
  [[ -n "$(compose_container pip-stub)" ]] && APF_E2E_PIP=1
  log "project ${COMPOSE_PROJECT_NAME}: ${running} container(s) running, OpenShell ${APF_E2E_OPENSHELL}, PIP ${APF_E2E_PIP}"
}

# compose_export_contract: the APF_E2E_* variables suites read.
compose_export_contract() {
  APF_E2E_OPENSHELL_CLI="$(openshell_cli_resolve)"
  APF_E2E_OPENSHELL_VERSION="${OPENSHELL_IMAGE_TAG}"
  APF_E2E_BUNDLE_DIGEST="${APF_E2E_WORK}/bundle-v1.digest"
  APF_E2E_APF_DIR="${APF_DIR}"
  if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
    APF_E2E_GATEWAY_URL="http://127.0.0.1:${OPENSHELL_PORT}"
    APF_E2E_HEALTH_URL="http://127.0.0.1:${OPENSHELL_HEALTH_PORT}"
  else
    APF_E2E_GATEWAY_URL=""
    APF_E2E_HEALTH_URL=""
  fi
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    APF_E2E_PIP_STUB_URL="http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}"
  else
    APF_E2E_PIP_STUB_URL=""
  fi
  export APF_E2E_ENV APF_E2E_OPENSHELL APF_E2E_PIP APF_E2E_WORK APF_E2E_LOG_DIR APF_E2E_GATEWAY_URL \
    APF_E2E_HEALTH_URL APF_E2E_OPENSHELL_CLI APF_E2E_OPENSHELL_VERSION APF_E2E_BUNDLE_DIGEST \
    APF_E2E_PIP_STUB_URL APF_E2E_SANDBOX_NAME APF_E2E_KEEP_SANDBOX APF_E2E_APF_DIR
}

compose_print_contract() {
  local v
  for v in APF_E2E_ENV APF_E2E_OPENSHELL APF_E2E_PIP APF_E2E_WORK APF_E2E_LOG_DIR APF_E2E_GATEWAY_URL \
    APF_E2E_HEALTH_URL APF_E2E_OPENSHELL_CLI APF_E2E_OPENSHELL_VERSION APF_E2E_BUNDLE_DIGEST \
    APF_E2E_PIP_STUB_URL APF_E2E_SANDBOX_NAME APF_E2E_KEEP_SANDBOX APF_E2E_APF_DIR; do
    printf '  %s=%s\n' "${v}" "${!v}"
  done
}
