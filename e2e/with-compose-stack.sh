#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# with-compose-stack.sh [--openshell] [--pip] [--build] [--keep] [--] <command...>
# with-compose-stack.sh [--openshell] [--pip] [--build]         bring the stack up and keep it
# with-compose-stack.sh --existing [--] <command...>           run against the kept stack
# with-compose-stack.sh --prepare [--openshell] [--pip]        materials and volumes only, nothing started
# with-compose-stack.sh --down [--volumes]                     tear the stack down
# with-compose-stack.sh --logs [component]                     follow the stack's logs
#
# Brings the APF compose stack (deploy/docker/compose.yaml) up, exports the
# APF_E2E_* contract (e2e/support/env.sh), runs the command with that
# environment and tears the stack down, volumes included, so every run starts
# clean. --openshell layers the OpenShell gateway overlay, --pip the provider
# lane, --build builds the two APF images first, --keep leaves the stack up.
# Without a command the stack stays up and the contract is printed; --existing
# runs a command against it and --down removes it (--volumes also resets the
# anti-rollback counter, the secrets and the OpenShell state). The knobs a run
# was rendered with are recorded in e2e/.work/compose/run.env and reused by
# --existing, --logs and --down.

set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_WORK="${E2E_WORK:-${E2E_DIR}/.work}"
RUN_ENV="${E2E_WORK}/compose/run.env"

usage() { sed -n '5,10p' "${BASH_SOURCE[0]}"; }

MODE=run
OPT_OPENSHELL=0
OPT_PIP=0
BUILD=0
KEEP=0
VOLUMES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --openshell) OPT_OPENSHELL=1 ;;
    --pip) OPT_PIP=1 ;;
    --build) BUILD=1 ;;
    --keep) KEEP=1 ;;
    --existing) MODE=existing ;;
    --prepare) MODE=prepare ;;
    --down) MODE=down ;;
    --volumes) VOLUMES=1 ;;
    --logs) MODE=logs ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
COMMAND=("$@")

case "${MODE}" in
  existing|down|logs)
    if [[ "${OPT_OPENSHELL}${OPT_PIP}${BUILD}${KEEP}" != 0000 ]]; then
      echo "--openshell, --pip, --build and --keep apply to a run; --${MODE} takes the stack as it is" >&2
      exit 2
    fi
    ;;
esac
if [[ "${VOLUMES}" == 1 && "${MODE}" != down ]]; then
  echo "--volumes applies to --down" >&2
  exit 2
fi
if [[ "${MODE}" == existing && ${#COMMAND[@]} -eq 0 ]]; then
  echo "--existing needs a command" >&2
  exit 2
fi
if [[ "${MODE}" == logs && ${#COMMAND[@]} -gt 1 ]]; then
  echo "--logs takes at most one component" >&2
  exit 2
fi

# The recorded knobs apply before the defaults, and after the caller's
# environment, which is why they are read first.
case "${MODE}" in
  existing|down|logs)
    if [[ -f "${RUN_ENV}" ]]; then
      # shellcheck source=/dev/null
      source "${RUN_ENV}"
    fi
    ;;
esac

# shellcheck source=support/common.sh
source "${E2E_DIR}/support/common.sh"
# shellcheck source=support/env-compose.sh
source "${E2E_DIR}/support/env-compose.sh"
# shellcheck source=support/materials.sh
source "${E2E_DIR}/support/materials.sh"
# shellcheck source=support/openshell.sh
source "${E2E_DIR}/support/openshell.sh"
# shellcheck source=support/compose-stack.sh
source "${E2E_DIR}/support/compose-stack.sh"

require_cmd docker
mkdir -p "${APF_E2E_WORK}" "${APF_E2E_LOG_DIR}"

# shellcheck disable=SC2086
write_knobs() { write_run_env "${RUN_ENV}" ${COMPOSE_RUN_KNOBS}; }

teardown() {
  banner "teardown (project ${COMPOSE_PROJECT_NAME})"
  compose_down "$1"
  rm -f "${RUN_ENV}"
}

case "${MODE}" in
  logs)
    # docker compose replaces this process, so ending the wrapper ends the
    # stream.
    files=()
    while IFS= read -r line; do files+=("${line}"); done < <(compose_files all)
    exec docker compose --project-directory "${COMPOSE_DIR}" "${files[@]}" logs -f "${COMMAND[@]+"${COMMAND[@]}"}"
    ;;
  down)
    if [[ "${VOLUMES}" == 1 ]]; then teardown volumes; else teardown keep; fi
    exit 0
    ;;
  existing)
    banner "APF compose stack, existing (project ${COMPOSE_PROJECT_NAME})"
    compose_detect_running
    [[ "${APF_E2E_OPENSHELL}" == 1 ]] && openshell_cli_ensure "${OPENSHELL_IMAGE_TAG}"
    compose_export_contract
    exec "${COMMAND[@]}"
    ;;
esac

# run and prepare modes: the lanes come from the options.
APF_E2E_OPENSHELL="${OPT_OPENSHELL}"
if [[ "${OPT_PIP}" == 1 ]]; then
  APF_E2E_PIP=1
  [[ -n "${PIP_CONFIG_SRC}" ]] || PIP_CONFIG_SRC="${E2E_DIR}/configs/pip/pips.yaml"
fi
export APF_E2E_OPENSHELL APF_E2E_PIP PIP_CONFIG_SRC BUILD
[[ ${#COMMAND[@]} -gt 0 ]] || KEEP=1

banner "APF compose verification (project ${COMPOSE_PROJECT_NAME})"
log "bundle: ${BUNDLE_SRC}"
log "OpenShell overlay: ${APF_E2E_OPENSHELL}; PIP lane: ${APF_E2E_PIP}"
log "work dir: ${APF_E2E_WORK}"
if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
  pin="$(openshell_proto_pin)"
  log "OpenShell under test: ${OPENSHELL_IMAGE_TAG} (${OPENSHELL_COMPUTE_DRIVER} driver); APF proto pin: ${pin:-unknown}"
  if [[ -n "${pin}" && "${pin}" != "${OPENSHELL_IMAGE_TAG}" ]]; then
    log "the versions differ: the extension protocol major version decides compatibility, and the gateway fails to start if it cannot negotiate with APF"
  fi
fi
write_knobs

if [[ "${MODE}" == prepare ]]; then
  materials_title="1/1 bundles, secrets, volumes"
  [[ "${APF_E2E_OPENSHELL}" == 1 ]] && materials_title+=", certificate, trust profiles, OpenShell material"
  step 0-preflight "0/1 preflight" compose_preflight
  step 1-materials "${materials_title}" compose_materials
  OPENSHELL_CLI="$(openshell_cli_resolve)"
  write_knobs
  banner "prepared"
  log "both bundle revisions are staged under ${APF_E2E_WORK}; the volumes of project ${COMPOSE_PROJECT_NAME} hold the secrets"
  log "start by hand with docker compose and deploy/docker/.env (see deploy/docker/README.md), or run: e2e/with-compose-stack.sh$([[ "${APF_E2E_OPENSHELL}" == 1 ]] && echo ' --openshell')$([[ "${APF_E2E_PIP}" == 1 ]] && echo ' --pip')"
  exit 0
fi

TEARDOWN_PENDING=0
on_exit() {
  local rc=$?
  if [[ "${TEARDOWN_PENDING}" == 1 ]]; then
    TEARDOWN_PENDING=0
    teardown volumes || true
  fi
  exit "${rc}"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

# Teardown is armed once preflight passed: a run that created nothing
# removes nothing, so a failed preflight (busy port, missing image) leaves a
# kept stack and its volumes as they are.
lifecycle() {
  step 0-preflight "0/3 preflight" compose_preflight || return 1
  [[ "${KEEP}" == 1 ]] || TEARDOWN_PENDING=1
  if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
    step 1-materials "1/3 bundles, secrets, certificate, trust profiles, OpenShell material" compose_materials || return 1
    step 2-up "2/3 docker compose up (pod, policy-service, policy-gateway$([[ "${APF_E2E_PIP}" == 1 ]] && echo ', pip-stub'), openshell-gateway)" compose_up || return 1
  else
    step 1-materials "1/3 bundles, secrets, volumes" compose_materials || return 1
    step 2-up "2/3 docker compose up (pod, policy-service, policy-gateway$([[ "${APF_E2E_PIP}" == 1 ]] && echo ', pip-stub'))" compose_up || return 1
  fi
  step 3-ready "3/3 stack ready" compose_ready || return 1
}

if ! lifecycle; then
  printf '\n%sstack did not come up; logs in %s%s\n' "${C_RED}" "${APF_E2E_LOG_DIR}" "${C_RESET}" >&2
  [[ "${KEEP}" == 1 ]] && log "stack kept for inspection (--keep); remove it with: e2e/with-compose-stack.sh --down --volumes"
  exit 1
fi

OPENSHELL_CLI="$(openshell_cli_resolve)"
compose_export_contract
write_knobs

if [[ ${#COMMAND[@]} -gt 0 ]]; then
  banner "running: ${COMMAND[*]}"
  rc=0
  "${COMMAND[@]}" || rc=$?
  if [[ "${KEEP}" == 1 ]]; then
    TEARDOWN_PENDING=0
    banner "stack kept (project ${COMPOSE_PROJECT_NAME})"
    compose_print_contract
    log "run another suite:  e2e/with-compose-stack.sh --existing <command>"
    log "follow the logs:    e2e/with-compose-stack.sh --logs [component]"
    log "tear down:          e2e/with-compose-stack.sh --down [--volumes]"
  fi
  exit "${rc}"
fi

TEARDOWN_PENDING=0
banner "stack up (project ${COMPOSE_PROJECT_NAME})"
compose_print_contract
log "run a suite:        e2e/with-compose-stack.sh --existing e2e/suites/smoke.sh"
log "follow the logs:    e2e/with-compose-stack.sh --logs [component]"
log "tear down:          e2e/with-compose-stack.sh --down [--volumes]"
