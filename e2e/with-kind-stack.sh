#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# with-kind-stack.sh [--pip] [--keep] [--] <command...>
# with-kind-stack.sh [--pip]                          bring the stack up and keep it
# with-kind-stack.sh --existing [--] <command...>     run against the kept stack
# with-kind-stack.sh --down [--cluster]               uninstall both releases; --cluster also deletes the cluster
# with-kind-stack.sh --logs [component]               follow a component's log
#
# Brings APF up with the Helm chart (deploy/helm/apf) on a kind cluster next
# to an OpenShell gateway installed from its own chart, exports the APF_E2E_*
# contract (e2e/support/env.sh) with port-forwards to the gateway, runs the
# command with that environment and uninstalls both releases afterwards; the
# cluster and its preloaded images stay for the next run. --pip adds the
# provider lane, --keep leaves the stack up. Without a command the stack stays
# up and the contract is printed; --existing runs a command against it and
# --down removes it. The knobs a run was rendered with are recorded in
# e2e/.work/kind/run.env and reused by --existing, --logs and --down.

set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_WORK="${E2E_WORK:-${E2E_DIR}/.work}"
RUN_ENV="${E2E_WORK}/kind/run.env"

usage() { sed -n '5,9p' "${BASH_SOURCE[0]}"; }

MODE=run
OPT_PIP=0
KEEP=0
CLUSTER=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pip) OPT_PIP=1 ;;
    --keep) KEEP=1 ;;
    --existing) MODE=existing ;;
    --down) MODE=down ;;
    --cluster) CLUSTER=1 ;;
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
    if [[ "${OPT_PIP}${KEEP}" != 00 ]]; then
      echo "--pip and --keep apply to a run; --${MODE} takes the stack as it is" >&2
      exit 2
    fi
    ;;
esac
if [[ "${CLUSTER}" == 1 && "${MODE}" != down ]]; then
  echo "--cluster applies to --down" >&2
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
# shellcheck source=support/env-kind.sh
source "${E2E_DIR}/support/env-kind.sh"
# shellcheck source=support/materials.sh
source "${E2E_DIR}/support/materials.sh"
# shellcheck source=support/openshell.sh
source "${E2E_DIR}/support/openshell.sh"
# shellcheck source=support/kind-cluster.sh
source "${E2E_DIR}/support/kind-cluster.sh"
# shellcheck source=support/kind-stack.sh
source "${E2E_DIR}/support/kind-stack.sh"

require_cmd kubectl helm kind yq docker
mkdir -p "${APF_E2E_WORK}" "${APF_E2E_LOG_DIR}"

# shellcheck disable=SC2086
write_knobs() { write_run_env "${RUN_ENV}" ${KIND_RUN_KNOBS}; }

teardown() {
  banner "teardown (cluster ${KIND_CLUSTER})"
  kind_forward_stop
  kind_forward_release
  kind_down "$1"
  rm -f "${RUN_ENV}"
}

case "${MODE}" in
  logs)
    # kubectl replaces this process, so ending the wrapper ends the stream.
    component="${COMMAND[0]:-}"
    case "${component}" in
      "") exec kubectl --context "${KIND_CONTEXT}" -n "${APF_NS}" logs -f "deployment/${APF_FULLNAME}" --all-containers ;;
      *) exec kubectl --context "${KIND_CONTEXT}" -n "$(component_ns "${component}")" logs -f "$(component_workload "${component}")" -c "$(component_container "${component}")" ;;
    esac
    ;;
  down)
    if [[ "${CLUSTER}" == 1 ]]; then teardown cluster; else teardown keep; fi
    exit 0
    ;;
  existing)
    banner "APF on kind, existing (cluster ${KIND_CLUSTER})"
    kind_detect_running
    openshell_cli_ensure "${OPENSHELL_VERSION}"
    trap kind_forward_stop EXIT
    kind_forward_start
    kind_export_contract
    rc=0
    "${COMMAND[@]}" || rc=$?
    exit "${rc}"
    ;;
esac

# run mode: the lanes come from the options.
if [[ "${OPT_PIP}" == 1 ]]; then
  APF_E2E_PIP=1
  [[ -n "${PIP_CONFIG_SRC}" ]] || PIP_CONFIG_SRC="${E2E_DIR}/configs/pip/pips.yaml"
fi
export APF_E2E_PIP PIP_CONFIG_SRC
[[ ${#COMMAND[@]} -gt 0 ]] || KEEP=1

banner "APF chart verification on kind (${KIND_CLUSTER})"
log "bundle: ${BUNDLE_SRC}"
log "PIP lane: ${APF_E2E_PIP}"
log "work dir: ${APF_E2E_WORK}"
pin="$(openshell_proto_pin)"
log "OpenShell under test: ${OPENSHELL_VERSION}; APF proto pin: ${pin:-unknown}"
if [[ -n "${pin}" && "${pin}" != "${OPENSHELL_VERSION}" ]]; then
  log "the versions differ: the extension protocol major version decides compatibility, and the registration step fails if the gateway cannot negotiate with APF"
fi
write_knobs

TEARDOWN_PENDING=0
on_exit() {
  local rc=$?
  kind_forward_stop
  if [[ "${TEARDOWN_PENDING}" == 1 ]]; then
    TEARDOWN_PENDING=0
    teardown keep || true
  fi
  exit "${rc}"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

# Teardown is armed once preflight passed: a run that created nothing
# removes nothing, so a failed preflight leaves a kept stack as it is.
lifecycle() {
  step 0-preflight "0/6 preflight" kind_preflight || return 1
  [[ "${KEEP}" == 1 ]] || TEARDOWN_PENDING=1
  step 1-cluster "1/6 kind cluster, agent-sandbox, images" kind_cluster_up || return 1
  # shellcheck source=/dev/null
  source "${NODE_IMAGES_ENV}"
  step 2-openshell "2/6 OpenShell ${OPENSHELL_VERSION} without extensions" kind_openshell_plain || return 1
  step 3-materials "3/6 bundles, certificate, trust profiles, Secrets and ConfigMaps" kind_materials || return 1
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    step 4-apf "4/6 APF chart with the pip-stub sidecar" install_apf || return 1
  else
    step 4-apf "4/6 APF chart" install_apf || return 1
  fi
  step 5-register "5/6 OpenShell with the APF registration overlay" register_apf_with_openshell || return 1
  banner "6/6 port-forwards"
  kind_forward_start
}

if ! lifecycle; then
  printf '\n%sstack did not come up; logs in %s%s\n' "${C_RED}" "${APF_E2E_LOG_DIR}" "${C_RESET}" >&2
  [[ "${KEEP}" == 1 ]] && log "releases kept for inspection (--keep); remove them with: e2e/with-kind-stack.sh --down"
  exit 1
fi

OPENSHELL_CLI="$(openshell_cli_resolve)"
kind_export_contract
write_knobs

if [[ ${#COMMAND[@]} -gt 0 ]]; then
  banner "running: ${COMMAND[*]}"
  rc=0
  "${COMMAND[@]}" || rc=$?
  if [[ "${KEEP}" == 1 ]]; then
    TEARDOWN_PENDING=0
    banner "stack kept (cluster ${KIND_CLUSTER})"
    kind_print_contract
    log "the port-forwards end with this process; --existing starts new ones"
    log "run another suite:  e2e/with-kind-stack.sh --existing <command>"
    log "follow the logs:    e2e/with-kind-stack.sh --logs [component]"
    log "tear down:          e2e/with-kind-stack.sh --down [--cluster]"
  fi
  exit "${rc}"
fi

TEARDOWN_PENDING=0
banner "stack up (cluster ${KIND_CLUSTER})"
kind_print_contract
log "the port-forwards end with this process; --existing starts new ones"
log "run a suite:        e2e/with-kind-stack.sh --existing e2e/suites/smoke.sh"
log "follow the logs:    e2e/with-kind-stack.sh --logs [component]"
log "tear down:          e2e/with-kind-stack.sh --down [--cluster]"
