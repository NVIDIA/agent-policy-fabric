#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# up.sh [--openshell] [--build]
#
# Brings the APF compose stack up and runs smoke.sh:
#   1. materials: signed bundle, secrets into the volumes   (materials.sh)
#   2. docker compose up -d                                 (pod -> policy-service -> policy-gateway)
#   3. smoke checks                                         (smoke.sh)
# --openshell layers compose.openshell.yaml: the materials include the serving
# certificate, the extension-JWT key pair and the trust profiles, the OpenShell
# gateway starts after the policy gateway is healthy, and the smoke checks
# admit a sandbox through APF.
# --build builds the two APF images from the repository Dockerfiles first.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

BUILD=0
for arg in "$@"; do
  case "${arg}" in
    --openshell) WITH_OPENSHELL=1 ;;
    --build) BUILD=1 ;;
    -h|--help) sed -n '5,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done
[[ "${WITH_OPENSHELL}" == 1 ]] || WITH_OPENSHELL=0
export WITH_OPENSHELL

require_cmd docker
LOG_DIR="${E2E_WORK}/logs"
mkdir -p "${E2E_WORK}" "${LOG_DIR}"

# step <slug> <title> <command...>: runs the command, tees its output to
# E2E_WORK/logs/<slug>.log, and dumps the stack state when it fails.
step() {
  local slug="$1" title="$2"
  shift 2
  banner "${title}"
  log "log: ${LOG_DIR}/${slug}.log"
  if ! "$@" 2>&1 | tee "${LOG_DIR}/${slug}.log"; then
    printf '\n%sstep failed: %s%s\n' "${C_RED}" "${title}" "${C_RESET}" >&2
    dump_stack_state
    exit 1
  fi
}

preflight() {
  docker info >/dev/null 2>&1 || fail "container engine not reachable through the docker CLI"
  docker compose version >/dev/null 2>&1 || fail "docker compose v2 is required"
  [[ "${APF_IMAGE_TAG}" != latest ]] || fail "APF_IMAGE_TAG=latest is refused; pin a tag"
  [[ "${OPENSHELL_IMAGE_TAG}" != latest ]] || fail "OPENSHELL_IMAGE_TAG=latest is refused; pin a tag"
  if [[ "${BUILD}" == 1 ]]; then
    log "building apf-policy-service:${APF_IMAGE_TAG} and apf-policy-gateway:${APF_IMAGE_TAG}"
    compose build policy-service policy-gateway
  fi
  local image
  for image in "apf-policy-service:${APF_IMAGE_TAG}" "apf-policy-gateway:${APF_IMAGE_TAG}"; do
    docker image inspect "${image}" >/dev/null 2>&1 || fail "image ${image} not found; build it (README step 2) or pass --build"
  done
  if [[ "${WITH_OPENSHELL}" == 1 ]]; then
    [[ -x "$(command -v "${OPENSHELL_CLI}" || true)" ]] || fail "OpenShell CLI ${OPENSHELL_IMAGE_TAG} not found; put openshell on PATH, set OPENSHELL_CLI, or drop the binary at ${E2E_WORK}/openshell"
    [[ -S "${CONTAINER_SOCKET}" || -e "${CONTAINER_SOCKET}" ]] || fail "CONTAINER_SOCKET not found: ${CONTAINER_SOCKET}"
    # The host-process half of the port check needs lsof.
    require_cmd lsof
    check_published_ports
  fi
  ok "preflight passed"
}

# check_published_ports: a port the overlay publishes must be free, or held
# by this project's own pod from an earlier run (compose recreates it). A
# container of another project or a host process is reported with the knob
# that moves the publish elsewhere.
check_published_ports() {
  local port pid cmd holder
  for port in "${OPENSHELL_PORT}" "${OPENSHELL_HEALTH_PORT}" "${APF_EGRESS_PORT}"; do
    holder="$(docker ps --filter "publish=${port}" --format '{{.Names}} {{.Label "com.docker.compose.project"}}' 2>/dev/null | head -n 1)"
    if [[ -n "${holder}" ]]; then
      if [[ "${holder##* }" == "${COMPOSE_PROJECT_NAME}" ]]; then
        log "port ${port} is published by this project's ${holder%% *}; compose will recreate it"
        continue
      fi
      fail "port 127.0.0.1:${port} is published by container ${holder%% *} (project '${holder##* }'); stop it or set OPENSHELL_PORT/OPENSHELL_HEALTH_PORT/APF_EGRESS_PORT"
    fi
    for pid in $(lsof -nP -tiTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true); do
      cmd="$(ps -o command= -p "${pid}" 2>/dev/null || true)"
      fail "port ${port} is held by host process ${pid} (${cmd:0:80}); stop it or set OPENSHELL_PORT/OPENSHELL_HEALTH_PORT/APF_EGRESS_PORT"
    done
  done
}

compose_up() {
  compose up -d --remove-orphans
  # The OpenShell gateway reads its TOML at startup and materials.sh renders
  # it from the environment on every run, so the container is recreated.
  [[ "${WITH_OPENSHELL}" == 1 ]] && compose up -d --no-deps --force-recreate openshell-gateway
  compose ps
}

banner "APF compose verification (project ${COMPOSE_PROJECT_NAME})"
log "bundle: ${BUNDLE_SRC}"
log "PIP enabled: ${PIP_ENABLED}"
log "OpenShell overlay: ${WITH_OPENSHELL}"
log "work dir: ${E2E_WORK}"
if [[ "${WITH_OPENSHELL}" == 1 ]]; then
  log "OpenShell under test: ${OPENSHELL_IMAGE_TAG} (${OPENSHELL_COMPUTE_DRIVER} driver); APF proto pin: ${APF_OPENSHELL_PIN:-unknown}"
  if [[ -n "${APF_OPENSHELL_PIN}" && "${APF_OPENSHELL_PIN}" != "${OPENSHELL_IMAGE_TAG}" ]]; then
    log "the versions differ: the extension protocol major version decides compatibility, and the gateway fails to start if it cannot negotiate with APF"
  fi
fi

step 0-preflight "0/3 preflight" preflight
if [[ "${WITH_OPENSHELL}" == 1 ]]; then
  step 1-materials "1/3 bundle, secrets, certificate, trust profiles, OpenShell material" "${E2E_DIR}/materials.sh" --openshell
  step 2-up "2/3 docker compose up (pod, policy-service, policy-gateway, openshell-gateway)" compose_up
else
  step 1-materials "1/3 bundle, secrets, volumes" "${E2E_DIR}/materials.sh"
  step 2-up "2/3 docker compose up (pod, policy-service, policy-gateway)" compose_up
fi
step 3-smoke "3/3 smoke checks" "${E2E_DIR}/smoke.sh"

banner "done"
if [[ "${WITH_OPENSHELL}" == 1 ]]; then
  log "inspect with: OPENSHELL_IMAGE_TAG=${OPENSHELL_IMAGE_TAG} OPENSHELL_STATE_DIR=${OPENSHELL_STATE_DIR} docker compose --project-directory ${COMPOSE_DIR} $(compose_files | tr '\n' ' ')ps"
else
  log "inspect with: docker compose --project-directory ${COMPOSE_DIR} $(compose_files | tr '\n' ' ')ps"
fi
log "tear down with: ${E2E_DIR}/down.sh [--volumes]"
