#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# smoke.sh: asserts that the APF compose stack serves decisions and, when the
# OpenShell overlay is up, that a real OpenShell gateway admits a sandbox
# through APF. Prints ok/FAIL per check and exits non-zero when any failed.
# KEEP_SANDBOX=1 leaves the test sandbox running.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

require_cmd docker
LOG_DIR="${E2E_WORK}/logs"
mkdir -p "${LOG_DIR}"

if [[ -z "${WITH_OPENSHELL}" ]]; then
  WITH_OPENSHELL=0
  openshell_container_present && WITH_OPENSHELL=1
fi
export WITH_OPENSHELL

SANDBOX_NAME="${SANDBOX_NAME:-apf-compose-e2e}"
AUDIT_DIR="/var/log/apf/audit"
EVALUATE_DIR="${APF_DIR}/examples/evaluate"
FAILED=0
SANDBOX_CREATED=0

cli() { "${OPENSHELL_CLI}" --gateway-endpoint "${OPENSHELL_GATEWAY_URL}" --gateway-insecure "$@"; }

check_failed() { printf '%s  FAIL %s%s\n' "${C_RED}" "$*" "${C_RESET}" >&2; FAILED=1; }

# check <title> <function>: runs the function and records its result.
check() {
  local title="$1" fn="$2"
  if "${fn}"; then ok "${title}"; else check_failed "${title}"; fi
}

cleanup() {
  if [[ "${SANDBOX_CREATED}" == 1 ]]; then
    if [[ "${KEEP_SANDBOX:-0}" == 1 ]]; then
      log "keeping sandbox ${SANDBOX_NAME} (KEEP_SANDBOX=1)"
    else
      cli sandbox delete "${SANDBOX_NAME}" >/dev/null 2>&1 && log "sandbox ${SANDBOX_NAME} deleted" || true
    fi
  fi
}
trap cleanup EXIT INT TERM

# wait_until <seconds> <function>: polls the function until it succeeds.
wait_until() {
  local deadline=$(( $(date +%s) + $1 ))
  shift
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    "$@" && return 0
    sleep 3
  done
  "$@"
}

# 1. Every container of the stack is running and, where it has a healthcheck,
# healthy. The policy gateway's healthcheck is the socket, or the egress
# listener with the overlay; the OpenShell gateway's readiness is checked
# separately over its health port.
containers_healthy_once() {
  local line name state health bad=0
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    read -r name state health <<<"${line}"
    if [[ "${state}" != running || ( -n "${health}" && "${health}" != healthy ) ]]; then
      bad=1
    fi
  done < <(compose ps -a --format '{{.Name}} {{.State}} {{.Health}}')
  [[ "${bad}" == 0 ]]
}
containers_healthy() {
  wait_until 120 containers_healthy_once || { compose ps -a; return 1; }
  compose ps -a | sed 's/^/  /'
}

# 2. The policy service verified the exact document materials.sh signed: the
# digest in its startup log equals the sha256 recorded next to the bundle.
bundle_verified_by_pap() {
  local expected logged
  expected="$(cat "${E2E_WORK}/bundle-v1.digest" 2>/dev/null || true)"
  [[ -n "${expected}" ]] || { log "no recorded digest at ${E2E_WORK}/bundle-v1.digest; run materials.sh"; return 1; }
  logged="$(compose logs --no-color --no-log-prefix policy-service 2>/dev/null \
    | strip_ansi | grep -o 'bundle verified and loaded.*' | tail -n 1 || true)"
  [[ -n "${logged}" ]] || { log "policy-service log has no 'bundle verified and loaded' line"; return 1; }
  echo "  ${logged}"
  [[ "${logged}" == *"digest=${expected}"* ]] || { log "logged digest differs from the signed document ${expected}"; return 1; }
}

# evaluate <request.json>: sends an EvaluateRequest over the gateway socket
# from the pinned grpcurl image, which attaches only the socket volume and the
# proto sources and runs as 65532 so the gateway's peer check admits it.
evaluate() {
  docker run --rm -i --user 65532:65532 \
    -v "$(volume_name apf-run):/run/apf" \
    -v "${APF_DIR}/contracts/proto:/proto:ro" \
    "${GRPCURL_IMAGE}" -plaintext \
    -import-path /proto -proto nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto \
    -d @ unix:///run/apf/policy-gateway/policy-gateway.sock \
    nvidia.agent_policy_fabric.pdp.v1alpha1.EvaluationService/Evaluate <"$1"
}

# 3. A decision over the socket for each shipped request, and the gateway's
# audit file records the decision under the same policy digest.
standalone_decision() {
  local out digest tail_out
  out="$(evaluate "${EVALUATE_DIR}/deny.json" 2>&1)" || { echo "${out}" >&2; return 1; }
  printf '%s\n' "${out}" >"${LOG_DIR}/evaluate-deny.json"
  echo "  deny.json  -> $(tr -d '\n' <<<"${out}" | tr -s ' ')"
  grep -q '"decision": "DECISION_DENY"' <<<"${out}" || { log "expected DECISION_DENY"; return 1; }
  out="$(evaluate "${EVALUATE_DIR}/allow.json" 2>&1)" || { echo "${out}" >&2; return 1; }
  printf '%s\n' "${out}" >"${LOG_DIR}/evaluate-allow.json"
  echo "  allow.json -> $(tr -d '\n' <<<"${out}" | tr -s ' ')"
  grep -q '"decision": "DECISION_ALLOW"' <<<"${out}" || { log "expected DECISION_ALLOW"; return 1; }
  digest="$(sed -n 's/.*"policyDigestHex": "\([0-9a-f]*\)".*/\1/p' <<<"${out}" | head -n 1)"
  [[ -n "${digest}" ]] || { log "response carries no policyDigestHex"; return 1; }
  tail_out="$(compose exec -T policy-gateway tail -n 1 "${AUDIT_DIR}/apf-policy-gateway-audit.jsonl" 2>/dev/null || true)"
  printf '%s\n' "${tail_out}" >"${LOG_DIR}/gateway-audit.tail.jsonl"
  [[ -n "${tail_out}" ]] || { log "gateway audit file is empty"; return 1; }
  echo "  audit: $(cut -c1-200 <<<"${tail_out}")..."
  grep -q "${digest}" <<<"${tail_out}" || { log "last gateway audit line does not carry digest ${digest}"; return 1; }
}

# save_gateway_log: writes the OpenShell gateway log to LOG_DIR with the ANSI
# colour codes removed, and prints it.
save_gateway_log() {
  compose logs --no-color --no-log-prefix openshell-gateway 2>/dev/null | strip_ansi | tee "${LOG_DIR}/openshell-gateway.log"
}

# 4. The OpenShell gateway negotiated with APF: it fails closed at startup when
# Describe on an extension fails, so a ready gateway that logged the binding
# count proves the registration.
gateway_ready_once() { curl -fsS -o /dev/null "${OPENSHELL_HEALTH_URL}/readyz" 2>/dev/null; }
gateway_registered_apf() {
  local line
  wait_until 180 gateway_ready_once || { log "OpenShell gateway not ready at ${OPENSHELL_HEALTH_URL}/readyz"; save_gateway_log | tail -n 40 >&2; return 1; }
  line="$(save_gateway_log | grep 'gateway interceptors initialized' | tail -n 1 || true)"
  [[ -n "${line}" ]] || { log "gateway log has no 'gateway interceptors initialized' line (saved to ${LOG_DIR}/openshell-gateway.log)"; return 1; }
  echo "  ${line##*gateway_interceptors::runtime: }"
  grep -q 'bindings=14 profile_sources=1' <<<"${line}" || { log "expected bindings=14 profile_sources=1"; return 1; }
}

# 5. The CLI reaches the gateway through the published port.
gateway_info() {
  cli gateway info >"${LOG_DIR}/gateway-info.txt" 2>&1 || { cat "${LOG_DIR}/gateway-info.txt" >&2; return 1; }
  sed 's/^/  /' "${LOG_DIR}/gateway-info.txt" | head -n 6
}

# 6. Sandbox admission stamps APF annotations on the created sandbox.
sandbox_annotations() {
  cli sandbox delete "${SANDBOX_NAME}" >/dev/null 2>&1 || true
  if ! cli sandbox create --name "${SANDBOX_NAME}" --detach -- sleep 3600 >"${LOG_DIR}/sandbox-create.log" 2>&1; then
    cat "${LOG_DIR}/sandbox-create.log" >&2
    return 1
  fi
  SANDBOX_CREATED=1
  local json="${LOG_DIR}/sandbox-${SANDBOX_NAME}.json"
  cli sandbox get "${SANDBOX_NAME}" -o json >"${json}" 2>"${LOG_DIR}/sandbox-get.log" || { cat "${LOG_DIR}/sandbox-get.log" >&2; return 1; }
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
  AUDIT_TAIL="$(compose exec -T policy-gateway tail -n 200 "${AUDIT_DIR}/apf-policy-gateway-interceptor-audit.jsonl" 2>/dev/null || true)"
  grep -q 'interceptor.policy_injected' <<<"${AUDIT_TAIL}"
}
admission_recorded() {
  EVAL_LINE="" AUDIT_TAIL=""
  wait_until 60 gateway_log_has_evaluation_once || { log "no 'gateway interceptor evaluated' line for apf/policy-adapter (log in ${LOG_DIR}/openshell-gateway.log)"; return 1; }
  echo "  ${EVAL_LINE##*gateway_interceptors::runtime: }"
  grep -q 'decision="allow"' <<<"${EVAL_LINE}" || { log "expected decision=\"allow\""; return 1; }
  wait_until 60 audit_has_injection_once
  local rc=$?
  printf '%s\n' "${AUDIT_TAIL}" >"${LOG_DIR}/interceptor-audit.tail.jsonl"
  [[ "${rc}" == 0 ]] || { log "interceptor audit file has no interceptor.policy_injected event"; return 1; }
  echo "  audit: $(grep 'interceptor.policy_injected' <<<"${AUDIT_TAIL}" | tail -n 1 | cut -c1-200)..."
}

# 8. The provider stub answers on the pod's loopback.
pip_stub_reachable() {
  local code url="http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}"
  code="$(compose exec -T policy-service curl -s -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || true)"
  [[ "${code}" == 200 ]] || { log "GET ${url} inside the pod returned '${code}'"; return 1; }
}

banner "smoke checks"
check "all containers running and healthy" containers_healthy
check "policy-service verified the signed bundle materials.sh built (digest matches)" bundle_verified_by_pap
check "decision over the gateway socket: deny.json denied, allow.json allowed, audit line carries the policy digest" standalone_decision
if [[ "${WITH_OPENSHELL}" == 1 ]]; then
  [[ -x "$(command -v "${OPENSHELL_CLI}" || true)" ]] || fail "OpenShell CLI not found; put openshell on PATH or set OPENSHELL_CLI"
  require_cmd curl
  check "OpenShell gateway ready and registered APF: 'gateway interceptors initialized bindings=14 profile_sources=1'" gateway_registered_apf
  check "openshell gateway info through ${OPENSHELL_GATEWAY_URL}" gateway_info
  check "sandbox admission: sandbox ${SANDBOX_NAME} created with apf.nvidia.com/bundle-id and provenance-token annotations" sandbox_annotations
  check "sandbox admission: gateway log records the apf/policy-adapter evaluation (allow) and the audit log interceptor.policy_injected" admission_recorded
else
  log "OpenShell overlay not running; checks 4-7 skipped (up.sh --openshell)"
fi
if [[ "${PIP_ENABLED}" == 1 ]]; then
  check "pip-stub answers GET http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH} inside the pod" pip_stub_reachable
else
  log "PIP disabled; pip-stub check skipped"
fi

if [[ "${FAILED}" == 1 ]]; then
  printf '\n%ssmoke checks failed; logs in %s%s\n' "${C_RED}" "${LOG_DIR}" "${C_RESET}" >&2
  exit 1
fi
ok "all smoke checks passed"
