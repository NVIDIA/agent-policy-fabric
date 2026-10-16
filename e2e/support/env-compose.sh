# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Compose environment: the knobs of the APF compose stack and the dispatch
# functions suites reach through e2e/support/env.sh. Sourced after common.sh.
# Every value can be overridden from the environment; e2e/with-compose-stack.sh
# exports the run's values before it runs a command, so a suite and the
# wrapper's --existing, --logs and --down address the same project.

COMPOSE_DIR="${APF_DIR}/deploy/docker"
# The compose project; the volumes are <project>_<volume>.
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-apf}"
# The gateway id names the extension-JWT issuer suffix, the audiences and,
# with the Docker driver, the namespace label the OpenShell gateway stamps on
# the sandbox containers it creates.
OPENSHELL_GATEWAY_ID="${OPENSHELL_GATEWAY_ID:-${COMPOSE_PROJECT_NAME}-compose}"
# docker | podman: the gateway TOML variant and the engine driving sandboxes.
OPENSHELL_COMPUTE_DRIVER="${OPENSHELL_COMPUTE_DRIVER:-docker}"
# The engine API socket as the engine resolves the bind source: with a Podman
# machine this is the path inside the machine, not the host-side socket named
# by DOCKER_HOST.
CONTAINER_SOCKET="${CONTAINER_SOCKET:-/var/run/docker.sock}"
# Published on 127.0.0.1 by the OpenShell overlay; the egress port is also the
# listener port because the host-network supervisor dials the same number.
OPENSHELL_PORT="${OPENSHELL_PORT:-8080}"
OPENSHELL_HEALTH_PORT="${OPENSHELL_HEALTH_PORT:-8081}"

APF_E2E_ENV=compose
APF_E2E_WORK="${E2E_WORK}/compose"
APF_E2E_LOG_DIR="${APF_E2E_WORK}/logs"
# OpenShell gateway state, bind-mounted at the same path inside its container.
OPENSHELL_STATE_DIR="${OPENSHELL_STATE_DIR:-${APF_E2E_WORK}/openshell-state}"
OPENSHELL_GATEWAY_TOML="${OPENSHELL_GATEWAY_TOML:-${APF_E2E_WORK}/openshell-gateway.toml}"
# What compose.yaml bind-mounts: the signed revision 1 and the trust root.
APF_BUNDLE_DIR="${APF_BUNDLE_DIR:-${APF_E2E_WORK}/bundle-v1/bundle}"
APF_TRUST_ROOT="${APF_TRUST_ROOT:-${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub}"
# The provider registration as the overlay mounts it.
PIP_CONFIG="${PIP_CONFIG:-${APF_E2E_WORK}/pips.yaml}"

# Lanes of the run. The wrapper sets them from its options; a non-empty
# PIP_CONFIG_SRC turns the provider lane on by itself.
APF_E2E_OPENSHELL="${APF_E2E_OPENSHELL:-0}"
APF_E2E_PIP="${APF_E2E_PIP:-0}"
[[ -n "${PIP_CONFIG_SRC}" ]] && APF_E2E_PIP=1
if [[ "${APF_E2E_PIP}" == 1 && -z "${PIP_CONFIG_SRC}" ]]; then
  PIP_CONFIG_SRC="${E2E_DIR}/configs/pip/pips.yaml"
fi

# Derived names. The audiences are OpenShell's extension-JWT strings:
# interceptor for sandbox admission, middleware for egress request policy.
OPENSHELL_JWT_ISSUER="openshell-gateway:${OPENSHELL_GATEWAY_ID}"
SERVICE_IMAGE="apf-policy-service:${APF_IMAGE_TAG}"
GATEWAY_IMAGE="apf-policy-gateway:${APF_IMAGE_TAG}"

# The knobs a run is rendered with, recorded in APF_E2E_WORK/run.env.
COMPOSE_RUN_KNOBS="COMPOSE_PROJECT_NAME OPENSHELL_GATEWAY_ID OPENSHELL_COMPUTE_DRIVER CONTAINER_SOCKET
  OPENSHELL_PORT OPENSHELL_HEALTH_PORT APF_ADMISSION_PORT APF_EGRESS_PORT OPENSHELL_STATE_DIR
  OPENSHELL_GATEWAY_TOML APF_BUNDLE_DIR APF_TRUST_ROOT APF_IMAGE_TAG APF_KEY_ID SIGNING_KEY_ID
  DEV_KEYS_DIR APF_COMPILE OPENSHELL_IMAGE_TAG OPENSHELL_IMAGE_REGISTRY SANDBOX_IMAGE GRPCURL_IMAGE
  OPENSHELL_CLI BUNDLE_SRC BUNDLE_V2_TRANSFORM PIP_CONFIG_SRC PIP_STUB_SRC PIP_STUB_IMAGE PIP_STUB_PORT
  PIP_STUB_HEALTH_PATH PIP_CONFIG APF_E2E_OPENSHELL APF_E2E_PIP"

export COMPOSE_DIR COMPOSE_PROJECT_NAME OPENSHELL_GATEWAY_ID OPENSHELL_COMPUTE_DRIVER CONTAINER_SOCKET \
  OPENSHELL_PORT OPENSHELL_HEALTH_PORT APF_E2E_ENV APF_E2E_WORK APF_E2E_LOG_DIR OPENSHELL_STATE_DIR \
  OPENSHELL_GATEWAY_TOML APF_BUNDLE_DIR APF_TRUST_ROOT PIP_CONFIG PIP_CONFIG_SRC APF_E2E_OPENSHELL \
  APF_E2E_PIP OPENSHELL_JWT_ISSUER

# compose_files [all]: the -f arguments of this run; `all` names every overlay
# (teardown, logs).
compose_files() {
  local args=(-f "${COMPOSE_DIR}/compose.yaml") openshell="${APF_E2E_OPENSHELL}" pip="${APF_E2E_PIP}"
  if [[ "${1:-}" == all ]]; then
    openshell=1 pip=1
  fi
  [[ "${openshell}" == 1 ]] && args+=(-f "${E2E_DIR}/configs/compose/compose.openshell.yaml")
  [[ "${pip}" == 1 ]] && args+=(-f "${E2E_DIR}/configs/compose/compose.pip.yaml")
  printf '%s\n' "${args[@]}"
}

# compose <args...>: docker compose for this project with the run's files
# (COMPOSE_FILES_SCOPE=all selects every overlay).
compose() {
  local files=() line
  while IFS= read -r line; do files+=("${line}"); done < <(compose_files "${COMPOSE_FILES_SCOPE:-}")
  docker compose --project-directory "${COMPOSE_DIR}" "${files[@]}" "$@"
}

# volume_name <key>: the engine-side name of a compose volume.
volume_name() { printf '%s_%s' "${COMPOSE_PROJECT_NAME}" "$1"; }

# compose_container <service>: the id of the project's container for a
# service, running or not; empty when there is none.
compose_container() {
  docker ps -a -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
    --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -n 1
}

# apf_e2e_ready <component>: running and, where the service has a
# healthcheck, healthy. `pod` is the pause container that owns the namespace.
apf_e2e_ready() {
  local line state health
  line="$(COMPOSE_FILES_SCOPE=all compose ps -a --format '{{.State}} {{.Health}}' "$1" 2>/dev/null | head -n 1)"
  [[ -n "${line}" ]] || return 1
  read -r state health <<<"${line}"
  [[ "${state}" == running ]] || return 1
  [[ -z "${health}" || "${health}" == healthy ]]
}

apf_e2e_logs() {
  COMPOSE_FILES_SCOPE=all compose logs --no-color --no-log-prefix "$1" 2>/dev/null | strip_ansi
}

apf_e2e_exec() {
  local component="$1"
  shift
  COMPOSE_FILES_SCOPE=all compose exec -T "${component}" "$@"
}

apf_e2e_audit_tail() {
  apf_e2e_exec "$1" tail -n "$3" "/var/log/apf/audit/$2"
}

# apf_e2e_evaluate <request.json>: sends the EvaluateRequest over the gateway
# socket from the pinned grpcurl image, which attaches only the socket volume
# and the proto sources and runs as 65532 so the gateway's peer check admits
# it. The container needs no network, writes nothing and holds no capability.
apf_e2e_evaluate() {
  local request="$1" out
  [[ -f "${request}" ]] || { echo "request file not found: ${request}" >&2; return 1; }
  if ! out="$(docker run --rm -i --user 65532:65532 \
      --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
      -v "$(volume_name apf-run):/run/apf" \
      -v "${APF_DIR}/contracts/proto:/proto:ro" \
      "${GRPCURL_IMAGE}" -plaintext \
      -import-path /proto -proto nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto \
      -d @ unix:///run/apf/policy-gateway/policy-gateway.sock \
      nvidia.agent_policy_fabric.pdp.v1alpha1.EvaluationService/Evaluate <"${request}" 2>&1)"; then
    printf '%s\n' "${out}" >&2
    return 1
  fi
  printf '%s\n' "${out}"
}

# Prints the containers of the project and the last log lines of every
# container that is not running or not healthy.
apf_e2e_dump_state() {
  echo "--- docker compose ps" >&2
  COMPOSE_FILES_SCOPE=all compose ps -a >&2 || true
  local line name state health
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    read -r name state health <<<"${line}"
    if [[ "${state}" != running || ( -n "${health}" && "${health}" != healthy ) ]]; then
      echo "--- logs ${name} (${state} ${health})" >&2
      docker logs --tail 80 "${name}" 2>&1 | strip_ansi >&2 || true
    fi
  done < <(COMPOSE_FILES_SCOPE=all compose ps -a --format '{{.Name}} {{.State}} {{.Health}}' 2>/dev/null || true)
}
