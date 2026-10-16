#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# smoke.sh: asserts that the APF stack of the current environment serves
# decisions and, when an OpenShell gateway is part of the run, that it admits
# a sandbox through APF. The suite runs unchanged against every environment
# through the contract a wrapper exports (e2e/with-compose-stack.sh,
# e2e/with-kind-stack.sh) and the dispatch functions of e2e/support/env.sh.
# Prints ok, FAIL or skip (with the reason) per check and exits 1 when any
# check failed; skips never fail. Artifacts land in APF_E2E_LOG_DIR.
# APF_E2E_KEEP_SANDBOX=1 leaves the test sandbox running.

set -euo pipefail
# shellcheck source=../support/env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/support/env.sh"

EVALUATE_DIR="${APF_E2E_APF_DIR}/examples/evaluate"
FAILED=0
SANDBOX_CREATED=0
SKIP_REASON=""

check_failed() { printf '%s  FAIL %s%s\n' "${C_RED}" "$*" "${C_RESET}" >&2; FAILED=1; }

# check <title> <function>: runs the function and records its result. A
# function returns 0 (ok), 1 (FAIL) or 2 (skip, reason in SKIP_REASON).
check() {
  local title="$1" fn="$2" rc=0
  SKIP_REASON=""
  "${fn}" || rc=$?
  case "${rc}" in
    0) ok "${title}" ;;
    2) skip "${title} (${SKIP_REASON})" ;;
    *) check_failed "${title}" ;;
  esac
}

cleanup() {
  if [[ "${SANDBOX_CREATED}" == 1 ]]; then
    if [[ "${APF_E2E_KEEP_SANDBOX}" == 1 ]]; then
      log "keeping sandbox ${APF_E2E_SANDBOX_NAME} (APF_E2E_KEEP_SANDBOX=1)"
    else
      cli sandbox delete "${APF_E2E_SANDBOX_NAME}" >/dev/null 2>&1 && log "sandbox ${APF_E2E_SANDBOX_NAME} deleted" || true
    fi
  fi
}
trap cleanup EXIT INT TERM

# 1. Every component of the run is running and ready: the two APF containers
# (healthy), the OpenShell gateway and the provider stub when they are part of
# the run.
components_ready_once() {
  local c
  for c in $(apf_e2e_components); do
    apf_e2e_ready "${c}" || return 1
  done
}
components_ready() {
  local c state
  if ! wait_until 120 components_ready_once; then
    for c in $(apf_e2e_components); do
      state=ready
      apf_e2e_ready "${c}" || state="not ready"
      log "${c}: ${state}"
    done
    return 1
  fi
  log "ready: $(apf_e2e_components | tr '\n' ' ')"
}

# 2. The policy service verified the exact document the wrapper signed: the
# digest in its startup log equals the sha256 recorded next to the bundle.
bundle_verified_by_pap() {
  local expected logged
  expected="$(cat "${APF_E2E_BUNDLE_DIGEST}" 2>/dev/null || true)"
  [[ -n "${expected}" ]] || { log "no recorded digest at ${APF_E2E_BUNDLE_DIGEST}"; return 1; }
  logged="$(apf_e2e_logs policy-service | grep -o 'bundle verified and loaded.*' | tail -n 1 || true)"
  [[ -n "${logged}" ]] || { log "policy-service log has no 'bundle verified and loaded' line"; return 1; }
  echo "  ${logged}"
  [[ "${logged}" == *"digest=${expected}"* ]] || { log "logged digest differs from the signed document ${expected}"; return 1; }
}

# 3. A decision over the gateway socket for each shipped request, and the
# gateway's audit file records the decision under the same policy digest.
# Where the environment cannot reach the socket the check is skipped.
socket_decision() {
  local out rc digest tail_out err="${APF_E2E_LOG_DIR}/evaluate.err"
  rc=0
  out="$(apf_e2e_evaluate "${EVALUATE_DIR}/deny.json" 2>"${err}")" || rc=$?
  if [[ "${rc}" == 2 ]]; then
    SKIP_REASON="$(tr -d '\n' <"${err}" | cut -c1-200)"
    return 2
  fi
  [[ "${rc}" == 0 ]] || { cat "${err}" >&2; return 1; }
  printf '%s\n' "${out}" >"${APF_E2E_LOG_DIR}/evaluate-deny.json"
  echo "  deny.json  -> $(tr -d '\n' <<<"${out}" | tr -s ' ')"
  grep -q '"decision": "DECISION_DENY"' <<<"${out}" || { log "expected DECISION_DENY"; return 1; }
  out="$(apf_e2e_evaluate "${EVALUATE_DIR}/allow.json" 2>"${err}")" || { cat "${err}" >&2; return 1; }
  printf '%s\n' "${out}" >"${APF_E2E_LOG_DIR}/evaluate-allow.json"
  echo "  allow.json -> $(tr -d '\n' <<<"${out}" | tr -s ' ')"
  grep -q '"decision": "DECISION_ALLOW"' <<<"${out}" || { log "expected DECISION_ALLOW"; return 1; }
  digest="$(sed -n 's/.*"policyDigestHex": "\([0-9a-f]*\)".*/\1/p' <<<"${out}" | head -n 1)"
  [[ -n "${digest}" ]] || { log "response carries no policyDigestHex"; return 1; }
  tail_out="$(apf_e2e_audit_tail policy-gateway apf-policy-gateway-audit.jsonl 1 2>/dev/null || true)"
  printf '%s\n' "${tail_out}" >"${APF_E2E_LOG_DIR}/gateway-audit.tail.jsonl"
  [[ -n "${tail_out}" ]] || { log "gateway audit file is empty"; return 1; }
  echo "  audit: $(cut -c1-200 <<<"${tail_out}")..."
  grep -q "${digest}" <<<"${tail_out}" || { log "last gateway audit line does not carry digest ${digest}"; return 1; }
}

# save_gateway_log: writes the OpenShell gateway log to APF_E2E_LOG_DIR and
# prints it.
save_gateway_log() {
  apf_e2e_logs openshell-gateway | tee "${APF_E2E_LOG_DIR}/openshell-gateway.log"
}

# gateway_message <line>: the gateway log line without its timestamp, level
# and module prefix; the interceptor runtime logs under several modules
# (openshell_gateway_interceptors::plan, ::runtime).
gateway_message() { sed 's/.*gateway_interceptors::[a-z_]*: //' <<<"$1"; }

# 4. The OpenShell gateway negotiated with APF: it fails closed at startup when
# Describe on an extension fails, so a ready gateway that logged the binding
# count proves the registration.
gateway_ready_once() { curl -fsS -o /dev/null "${APF_E2E_HEALTH_URL}/readyz" 2>/dev/null; }
gateway_registered_apf() {
  local line
  wait_until 180 gateway_ready_once || { log "OpenShell gateway not ready at ${APF_E2E_HEALTH_URL}/readyz"; save_gateway_log | tail -n 40 >&2; return 1; }
  line="$(save_gateway_log | grep 'gateway interceptors initialized' | tail -n 1 || true)"
  [[ -n "${line}" ]] || { log "gateway log has no 'gateway interceptors initialized' line (saved to ${APF_E2E_LOG_DIR}/openshell-gateway.log)"; return 1; }
  echo "  $(gateway_message "${line}")"
  grep -q 'bindings=14 profile_sources=1' <<<"${line}" || { log "expected bindings=14 profile_sources=1"; return 1; }
}

# 5. The CLI reaches the gateway.
gateway_info() {
  cli gateway info >"${APF_E2E_LOG_DIR}/gateway-info.txt" 2>&1 || { cat "${APF_E2E_LOG_DIR}/gateway-info.txt" >&2; return 1; }
  sed 's/^/  /' "${APF_E2E_LOG_DIR}/gateway-info.txt" | head -n 6
}

# 6. Sandbox admission stamps APF annotations on the created sandbox.
sandbox_annotations() {
  local json="${APF_E2E_LOG_DIR}/sandbox-${APF_E2E_SANDBOX_NAME}.json"
  cli sandbox delete "${APF_E2E_SANDBOX_NAME}" >/dev/null 2>&1 || true
  if ! cli sandbox create --name "${APF_E2E_SANDBOX_NAME}" --detach -- sleep 3600 >"${APF_E2E_LOG_DIR}/sandbox-create.log" 2>&1; then
    cat "${APF_E2E_LOG_DIR}/sandbox-create.log" >&2
    return 1
  fi
  SANDBOX_CREATED=1
  cli sandbox get "${APF_E2E_SANDBOX_NAME}" -o json >"${json}" 2>"${APF_E2E_LOG_DIR}/sandbox-get.log" || { cat "${APF_E2E_LOG_DIR}/sandbox-get.log" >&2; return 1; }
  echo "  annotations:"
  grep -o '"apf.nvidia.com/[^"]*": *"[^"]\{0,60\}' "${json}" | sed 's/^/    /' || true
  grep -q 'apf.nvidia.com/bundle-id' "${json}" && grep -q 'apf.nvidia.com/provenance-token' "${json}"
}

# 7. The gateway log records the admission evaluation and the sandbox
# admission audit file records the policy injection.
gateway_log_has_evaluation_once() {
  EVAL_LINE="$(save_gateway_log | grep 'gateway interceptor evaluated' | grep 'interceptor=apf/policy-adapter' | tail -n 1 || true)"
  [[ -n "${EVAL_LINE}" ]]
}
audit_has_injection_once() {
  AUDIT_TAIL="$(apf_e2e_audit_tail policy-gateway apf-policy-gateway-interceptor-audit.jsonl 200 2>/dev/null || true)"
  grep -q 'interceptor.policy_injected' <<<"${AUDIT_TAIL}"
}
admission_recorded() {
  EVAL_LINE="" AUDIT_TAIL=""
  wait_until 60 gateway_log_has_evaluation_once || { log "no 'gateway interceptor evaluated' line for apf/policy-adapter (log in ${APF_E2E_LOG_DIR}/openshell-gateway.log)"; return 1; }
  echo "  $(gateway_message "${EVAL_LINE}")"
  grep -q 'decision="allow"' <<<"${EVAL_LINE}" || { log "expected decision=\"allow\""; return 1; }
  local rc=0
  wait_until 60 audit_has_injection_once || rc=$?
  printf '%s\n' "${AUDIT_TAIL}" >"${APF_E2E_LOG_DIR}/interceptor-audit.tail.jsonl"
  [[ "${rc}" == 0 ]] || { log "interceptor audit file has no interceptor.policy_injected event"; return 1; }
  echo "  audit: $(grep 'interceptor.policy_injected' <<<"${AUDIT_TAIL}" | tail -n 1 | cut -c1-200)..."
}

# 8. The provider stub is ready and answers on the pod's loopback; the
# policy-service image carries curl.
pip_stub_reachable() {
  local code
  apf_e2e_ready pip-stub || { log "pip-stub is not ready"; return 1; }
  code="$(apf_e2e_exec policy-service curl -s -o /dev/null -w '%{http_code}' "${APF_E2E_PIP_STUB_URL}" 2>/dev/null || true)"
  [[ "${code}" == 200 ]] || { log "GET ${APF_E2E_PIP_STUB_URL} inside the pod returned '${code}'"; return 1; }
}

banner "smoke checks (${APF_E2E_ENV})"
check "every component running and ready" components_ready
check "policy-service verified the signed bundle (digest matches the recorded document)" bundle_verified_by_pap
check "decision over the gateway socket: deny.json denied, allow.json allowed, audit line carries the policy digest" socket_decision
if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then
  [[ -n "${APF_E2E_OPENSHELL_CLI}" && -x "${APF_E2E_OPENSHELL_CLI}" ]] || fail "APF_E2E_OPENSHELL_CLI is not an executable OpenShell CLI: '${APF_E2E_OPENSHELL_CLI}'"
  require_cmd curl
  check "OpenShell gateway ready and registered APF: 'gateway interceptors initialized bindings=14 profile_sources=1'" gateway_registered_apf
  check "openshell gateway info through ${APF_E2E_GATEWAY_URL}" gateway_info
  check "sandbox admission: sandbox ${APF_E2E_SANDBOX_NAME} created with apf.nvidia.com/bundle-id and provenance-token annotations" sandbox_annotations
  check "sandbox admission: gateway log records the apf/policy-adapter evaluation (allow) and the audit log interceptor.policy_injected" admission_recorded
else
  skip "checks 4-7 (OpenShell gateway not part of this run)"
fi
if [[ "${APF_E2E_PIP}" == 1 ]]; then
  check "pip-stub ready and GET ${APF_E2E_PIP_STUB_URL} returns 200 inside the pod" pip_stub_reachable
else
  skip "check 8 (provider lane not part of this run)"
fi

if [[ "${FAILED}" == 1 ]]; then
  printf '\n%ssmoke checks failed; artifacts in %s%s\n' "${C_RED}" "${APF_E2E_LOG_DIR}" "${C_RESET}" >&2
  exit 1
fi
ok "all smoke checks passed"
