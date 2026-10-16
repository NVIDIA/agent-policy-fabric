# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The contract a suite sources. A wrapper (e2e/with-compose-stack.sh,
# e2e/with-kind-stack.sh) exports APF_E2E_ENV and the APF_E2E_* variables
# before it runs the suite; this file loads the shared helpers, the dispatch
# functions of that environment and the OpenShell CLI call. Suites use only
# these and never call docker, kubectl or helm themselves.
#
# Dispatch functions every environment file defines:
#   apf_e2e_ready <component>                      0 when the component is running and ready
#   apf_e2e_logs <component>                       current log on stdout, ANSI codes stripped
#   apf_e2e_exec <component> <command...>          run a command in the component
#   apf_e2e_audit_tail <component> <file> <n>      last n lines of /var/log/apf/audit/<file>
#   apf_e2e_evaluate <request.json>                EvaluateRequest over the gateway socket:
#                                                  0 + response on stdout; 1 failed, reason on
#                                                  stderr; 2 unsupported here, reason on stderr
#   apf_e2e_dump_state                             state of the stack on stderr
# Components: policy-service, policy-gateway, openshell-gateway, pip-stub.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

[[ -n "${APF_E2E_ENV:-}" ]] || fail "APF_E2E_ENV is unset; run this suite through e2e/with-compose-stack.sh or e2e/with-kind-stack.sh"
[[ -f "${E2E_DIR}/support/env-${APF_E2E_ENV}.sh" ]] || fail "unknown environment APF_E2E_ENV=${APF_E2E_ENV}: e2e/support/env-${APF_E2E_ENV}.sh does not exist"
# shellcheck source=/dev/null
source "${E2E_DIR}/support/env-${APF_E2E_ENV}.sh"
# shellcheck source=openshell.sh
source "${E2E_DIR}/support/openshell.sh"

for _v in APF_E2E_WORK APF_E2E_LOG_DIR APF_E2E_BUNDLE_DIGEST; do
  [[ -n "${!_v:-}" ]] || fail "${_v} is unset; the wrapper exports it before running a suite"
done
unset _v
mkdir -p "${APF_E2E_LOG_DIR}"

# apf_e2e_components: the components of this run, one per line, from the
# APF_E2E_OPENSHELL and APF_E2E_PIP flags.
apf_e2e_components() {
  printf 'policy-service\npolicy-gateway\n'
  [[ "${APF_E2E_OPENSHELL:-0}" == 1 ]] && printf 'openshell-gateway\n'
  [[ "${APF_E2E_PIP:-0}" == 1 ]] && printf 'pip-stub\n'
  return 0
}
