# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Shared variables and helpers for the APF compose verification harness.
# Source this file; every value can be overridden from the environment.
# Defaults stay inside this repository so the harness runs from a clone of apf
# alone; a demo composes it by pointing the knobs below at its own material.

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(cd "${E2E_DIR}/.." && pwd)"
APF_DIR="$(cd "${COMPOSE_DIR}/../.." && pwd)"

# The compose project; the volumes are <project>_<volume>.
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-apf}"
APF_IMAGE_TAG="${APF_IMAGE_TAG:-dev}"
APF_KEY_ID="${APF_KEY_ID:-apf-dev}"
OPENSHELL_IMAGE_TAG="${OPENSHELL_IMAGE_TAG:-0.1.3}"
OPENSHELL_IMAGE_REGISTRY="${OPENSHELL_IMAGE_REGISTRY:-ghcr.io/nvidia/openshell}"
OPENSHELL_GATEWAY_ID="${OPENSHELL_GATEWAY_ID:-apf-compose}"
OPENSHELL_COMPUTE_DRIVER="${OPENSHELL_COMPUTE_DRIVER:-docker}"
CONTAINER_SOCKET="${CONTAINER_SOCKET:-/var/run/docker.sock}"
# Published on 127.0.0.1 by the overlay; the egress port is also the listener
# port because the host-network supervisor dials the same number.
OPENSHELL_PORT="${OPENSHELL_PORT:-8080}"
OPENSHELL_HEALTH_PORT="${OPENSHELL_HEALTH_PORT:-8081}"
APF_ADMISSION_PORT="${APF_ADMISSION_PORT:-18081}"
APF_EGRESS_PORT="${APF_EGRESS_PORT:-9099}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:e29a8e98c1399aa08a8c624d758d1814b6edbe0302eb570c0468a6d3e811d167}"
GRPCURL_IMAGE="${GRPCURL_IMAGE:-fullstorydev/grpcurl@sha256:085e183ca334eb4e81ca81ee12cbb2b2737505d1d77f5e33dabc5d066593d998}"

E2E_WORK="${E2E_WORK:-${E2E_DIR}/.work}"
# OpenShell gateway state, bind-mounted at the same path inside its container.
OPENSHELL_STATE_DIR="${OPENSHELL_STATE_DIR:-${E2E_WORK}/openshell-state}"
OPENSHELL_GATEWAY_TOML="${OPENSHELL_GATEWAY_TOML:-${E2E_WORK}/openshell-gateway.toml}"

# The policy bundle source: a directory holding one *.template.yaml and the
# member files it lists. Revision 2 bumps policy_revision; BUNDLE_V2_TRANSFORM
# may name an executable that receives the staged directory and edits members
# before signing.
BUNDLE_SRC="${BUNDLE_SRC:-${APF_DIR}/examples/demo-bundle}"
BUNDLE_V2_TRANSFORM="${BUNDLE_V2_TRANSFORM:-}"
# What compose.yaml bind-mounts: the signed revision 1 and the trust root.
APF_BUNDLE_DIR="${APF_BUNDLE_DIR:-${E2E_WORK}/bundle-v1/bundle}"
DEV_KEYS_DIR="${DEV_KEYS_DIR:-${APF_DIR}/examples/dev-keys}"
SIGNING_KEY_ID="${SIGNING_KEY_ID:-${APF_KEY_ID}}"
APF_TRUST_ROOT="${APF_TRUST_ROOT:-${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub}"
APF_COMPILE="${APF_COMPILE:-${APF_DIR}/target/release/apf-compile}"

# Policy information provider lane, off unless PIP_CONFIG_SRC names a
# registration (the in-repo fixture is ../../helm/e2e/fixtures/pip/pips.yaml).
# The stub script is served from the pod's loopback by a sidecar; it must
# accept --port and answer PIP_STUB_HEALTH_PATH with 200.
PIP_CONFIG_SRC="${PIP_CONFIG_SRC:-}"
PIP_STUB_SRC="${PIP_STUB_SRC:-${APF_DIR}/deploy/helm/e2e/fixtures/pip/stub.py}"
PIP_STUB_IMAGE="${PIP_STUB_IMAGE:-python:3.12-slim}"
PIP_STUB_PORT="${PIP_STUB_PORT:-19500}"
PIP_STUB_HEALTH_PATH="${PIP_STUB_HEALTH_PATH:-/healthz}"
PIP_CONFIG="${PIP_CONFIG:-${E2E_WORK}/pips.yaml}"
PIP_ENABLED=0
[[ -n "${PIP_CONFIG_SRC}" ]] && PIP_ENABLED=1

# The OpenShell overlay is part of the run when WITH_OPENSHELL=1 (up.sh
# --openshell); smoke.sh and down.sh default to whatever is running.
WITH_OPENSHELL="${WITH_OPENSHELL:-}"

# The OpenShell release whose protos the APF binaries were generated from, read
# from the pin in crates/apf-proto/build.rs (the comment after the commit).
APF_OPENSHELL_PIN="$(sed -n 's/^const OPENSHELL_COMMIT.*\/\/ *v\{0,1\}\([0-9][0-9.]*\).*/\1/p' "${APF_DIR}/crates/apf-proto/build.rs" 2>/dev/null | head -n 1)"

# The OpenShell CLI: a binary in a harness work directory wins, else
# `openshell` on PATH.
if [[ -z "${OPENSHELL_CLI:-}" ]]; then
  OPENSHELL_CLI="openshell"
  if [[ -x "${E2E_WORK}/openshell" ]]; then
    OPENSHELL_CLI="${E2E_WORK}/openshell"
  elif [[ -x "${APF_DIR}/deploy/helm/e2e/.work/openshell" ]]; then
    OPENSHELL_CLI="${APF_DIR}/deploy/helm/e2e/.work/openshell"
  fi
fi

# Derived names. The audiences are OpenShell's extension-JWT strings:
# interceptor for sandbox admission, middleware for egress request policy.
OPENSHELL_JWT_ISSUER="openshell-gateway:${OPENSHELL_GATEWAY_ID}"
INTERCEPTOR_AUDIENCE="urn:openshell:extension:interceptor:${OPENSHELL_GATEWAY_ID}"
MIDDLEWARE_AUDIENCE="urn:openshell:extension:middleware:${OPENSHELL_GATEWAY_ID}"
OPENSHELL_GATEWAY_URL="http://127.0.0.1:${OPENSHELL_PORT}"
OPENSHELL_HEALTH_URL="http://127.0.0.1:${OPENSHELL_HEALTH_PORT}"

export E2E_DIR COMPOSE_DIR APF_DIR COMPOSE_PROJECT_NAME APF_IMAGE_TAG APF_KEY_ID \
  OPENSHELL_IMAGE_TAG OPENSHELL_IMAGE_REGISTRY OPENSHELL_GATEWAY_ID OPENSHELL_COMPUTE_DRIVER \
  CONTAINER_SOCKET OPENSHELL_PORT OPENSHELL_HEALTH_PORT APF_ADMISSION_PORT APF_EGRESS_PORT \
  SANDBOX_IMAGE GRPCURL_IMAGE E2E_WORK OPENSHELL_STATE_DIR OPENSHELL_GATEWAY_TOML \
  BUNDLE_SRC BUNDLE_V2_TRANSFORM APF_BUNDLE_DIR DEV_KEYS_DIR SIGNING_KEY_ID APF_TRUST_ROOT APF_COMPILE \
  PIP_CONFIG_SRC PIP_STUB_SRC PIP_STUB_IMAGE PIP_STUB_PORT PIP_STUB_HEALTH_PATH PIP_CONFIG PIP_ENABLED \
  WITH_OPENSHELL APF_OPENSHELL_PIN OPENSHELL_CLI \
  OPENSHELL_JWT_ISSUER INTERCEPTOR_AUDIENCE MIDDLEWARE_AUDIENCE OPENSHELL_GATEWAY_URL OPENSHELL_HEALTH_URL

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m' C_BOLD=$'\033[1m' C_GREEN=$'\033[1;32m' C_RED=$'\033[1;31m' C_DIM=$'\033[2m'
else
  C_RESET="" C_BOLD="" C_GREEN="" C_RED="" C_DIM=""
fi

log()    { printf '%s  %s%s\n' "${C_DIM}" "$*" "${C_RESET}"; }
banner() { printf '\n%s== %s ==%s\n' "${C_BOLD}" "$*" "${C_RESET}"; }
ok()     { printf '%s  ok   %s%s\n' "${C_GREEN}" "$*" "${C_RESET}"; }
fail()   { printf '%s  FAIL %s%s\n' "${C_RED}" "$*" "${C_RESET}" >&2; exit 1; }

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || fail "required command not found on PATH: $c"
  done
}

# Removes the ANSI colour codes the OpenShell gateway writes into its log.
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g'; }

# True when the OpenShell gateway container of this project exists.
openshell_container_present() {
  [[ -n "$(docker ps -a -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
    --filter "label=com.docker.compose.service=openshell-gateway" 2>/dev/null)" ]]
}

# compose_files [all]: the -f arguments for this run. The OpenShell overlay is
# included when WITH_OPENSHELL=1, or when its container already exists and
# WITH_OPENSHELL is unset; `all` includes every overlay (teardown).
compose_files() {
  local args=(-f "${COMPOSE_DIR}/compose.yaml") openshell="${WITH_OPENSHELL}" pip="${PIP_ENABLED}"
  if [[ "${1:-}" == all ]]; then
    openshell=1 pip=1
  elif [[ -z "${openshell}" ]]; then
    openshell=0
    openshell_container_present && openshell=1
  fi
  [[ "${openshell}" == 1 ]] && args+=(-f "${E2E_DIR}/compose.openshell.yaml")
  [[ "${pip}" == 1 ]] && args+=(-f "${E2E_DIR}/compose.pip.yaml")
  printf '%s\n' "${args[@]}"
}

# compose <args...>: docker compose for this project with the run's files.
compose() {
  local files=()
  while IFS= read -r line; do files+=("${line}"); done < <(compose_files "${COMPOSE_FILES_SCOPE:-}")
  docker compose --project-directory "${COMPOSE_DIR}" "${files[@]}" "$@"
}

# volume_name <key>: the engine-side name of a compose volume.
volume_name() { printf '%s_%s' "${COMPOSE_PROJECT_NAME}" "$1"; }

# Prints the containers of the project and the last log lines of every
# container that is not running or not healthy. Called by steps that fail.
dump_stack_state() {
  echo "--- docker compose ps" >&2
  compose ps -a >&2 || true
  local line name state health
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    read -r name state health <<<"${line}"
    if [[ "${state}" != running || ( -n "${health}" && "${health}" != healthy ) ]]; then
      echo "--- logs ${name} (${state} ${health})" >&2
      docker logs --tail 80 "${name}" 2>&1 | strip_ansi >&2 || true
    fi
  done < <(compose ps -a --format '{{.Name}} {{.State}} {{.Health}}' 2>/dev/null || true)
}
