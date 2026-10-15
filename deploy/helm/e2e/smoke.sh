#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# smoke.sh: asserts that APF serves a real OpenShell gateway on the kind cluster.
# Prints ok/FAIL per check and exits non-zero when any check failed.
# KEEP_SANDBOX=1 leaves the test sandbox running.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

require_cmd kubectl yq
[[ -x "$(command -v "${OPENSHELL_CLI}" || true)" ]] || fail "OpenShell CLI ${OPENSHELL_VERSION} not found; put openshell on PATH or set OPENSHELL_CLI"
LOG_DIR="${E2E_WORK}/logs"
mkdir -p "${LOG_DIR}"

SANDBOX_NAME="${SANDBOX_NAME:-apf-e2e}"
LOCAL_PORT="${OPENSHELL_LOCAL_PORT:-18080}"
GATEWAY_LOCAL="http://127.0.0.1:${LOCAL_PORT}"
AUDIT_FILE="/var/log/apf/audit/apf-policy-gateway-interceptor-audit.jsonl"
FAILED=0
PF_PID=""
SANDBOX_CREATED=0

cli() { "${OPENSHELL_CLI}" --gateway-endpoint "${GATEWAY_LOCAL}" --gateway-insecure "$@"; }

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
  if [[ -n "${PF_PID}" ]]; then
    kill "${PF_PID}" 2>/dev/null || true
    wait "${PF_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# 1. APF deployment Ready.
apf_ready() {
  wait_for_rollout "${APF_NS}" "deployment/${APF_FULLNAME}" 120s >/dev/null
}

# 1b. The policy service verified the exact document materials.sh signed: the
# digest in its startup log equals the sha256 recorded next to the tarball.
bundle_verified_by_pap() {
  local expected logged
  expected="$(cat "${E2E_WORK}/bundle-v1.digest" 2>/dev/null || true)"
  [[ -n "${expected}" ]] || { log "no recorded digest at ${E2E_WORK}/bundle-v1.digest; run materials.sh"; return 1; }
  logged="$(kctl -n "${APF_NS}" logs "deployment/${APF_FULLNAME}" -c policy-service 2>/dev/null \
    | sed $'s/\x1b\\[[0-9;]*m//g' | grep -o 'bundle verified and loaded.*' | tail -n 1 || true)"
  [[ -n "${logged}" ]] || { log "policy-service log has no 'bundle verified and loaded' line"; return 1; }
  echo "  ${logged}"
  [[ "${logged}" == *"digest=${expected}"* ]] || { log "logged digest differs from the signed document ${expected}"; return 1; }
}

# 2. The gateway runs with APF registered: gateway.toml names both features
# (sandbox admission as interceptor apf/policy-adapter, egress request policy
# as middleware apf-content-policy) and the provider-profile source, and the
# StatefulSet rolled out with that config.
# The gateway fails closed at startup when Describe on an extension fails, so a
# Ready gateway proves the negotiation.
gateway_registered_apf() {
  local toml
  toml="$(kctl -n "${OPENSHELL_NS}" get configmap "${OPENSHELL_RELEASE}-config" -o jsonpath='{.data.gateway\.toml}' 2>/dev/null || true)"
  printf '%s\n' "${toml}" >"${LOG_DIR}/openshell-gateway.toml"
  grep -q 'name = "apf/policy-adapter"' <<<"${toml}" || { log "gateway.toml lacks the sandbox admission interceptor apf/policy-adapter"; return 1; }
  grep -q 'name = "apf-content-policy"' <<<"${toml}" || { log "gateway.toml lacks the egress request policy middleware apf-content-policy"; return 1; }
  grep -q 'provider_profile_sources = \[{ name = "apf/policy-adapter"' <<<"${toml}" || { log "gateway.toml lacks the apf/policy-adapter provider-profile source"; return 1; }
  wait_for_rollout "${OPENSHELL_NS}" "statefulset/${OPENSHELL_RELEASE}" 120s >/dev/null
}

# save_gateway_log: writes the current gateway pod logs to LOG_DIR, with the
# ANSI colour codes the gateway emits removed, and prints them.
save_gateway_log() {
  local pods pod logs=""
  pods="$(kctl -n "${OPENSHELL_NS}" get pods -l "app.kubernetes.io/name=openshell,app.kubernetes.io/instance=${OPENSHELL_RELEASE}" -o name 2>/dev/null || true)"
  for pod in ${pods}; do
    logs+="$(kctl -n "${OPENSHELL_NS}" logs "${pod}" --tail=-1 2>/dev/null || true)"$'\n'
  done
  printf '%s' "${logs}" | sed $'s/\x1b\\[[0-9;]*m//g' | tee "${LOG_DIR}/openshell-gateway.log"
}

# release_local_port: ends a kubectl port-forward left on LOCAL_PORT by an
# interrupted run; any other listener is reported and the check fails.
release_local_port() {
  local pid cmd
  for pid in $(lsof -nP -tiTCP:"${LOCAL_PORT}" -sTCP:LISTEN 2>/dev/null || true); do
    cmd="$(ps -o command= -p "${pid}" 2>/dev/null || true)"
    if [[ "${cmd}" == *"kubectl"*"port-forward"* ]]; then
      log "ending stale port-forward (pid ${pid}) on ${LOCAL_PORT}"
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    else
      log "port ${LOCAL_PORT} is held by another process (pid ${pid}): ${cmd}; set OPENSHELL_LOCAL_PORT"
      return 1
    fi
  done
}

# 3. Port-forward and CLI gateway info.
gateway_info() {
  release_local_port || return 1
  kctl -n "${OPENSHELL_NS}" port-forward "svc/${OPENSHELL_SERVICE}" "${LOCAL_PORT}:${OPENSHELL_SERVICE_PORT}" \
    >"${LOG_DIR}/port-forward.log" 2>&1 &
  PF_PID=$!
  local deadline=$(( $(date +%s) + 60 ))
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    if grep -q "address already in use\|unable to listen" "${LOG_DIR}/port-forward.log" 2>/dev/null; then
      cat "${LOG_DIR}/port-forward.log" >&2
      return 1
    fi
    if cli gateway info >"${LOG_DIR}/gateway-info.txt" 2>&1; then
      return 0
    fi
    kill -0 "${PF_PID}" 2>/dev/null || { cat "${LOG_DIR}/port-forward.log" >&2; return 1; }
    sleep 2
  done
  cat "${LOG_DIR}/gateway-info.txt" >&2
  return 1
}

# 4. Sandbox admission stamps APF annotations on the created sandbox.
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
  yq -p json -o json '.. | select(type == "!!map" and has("apf.nvidia.com/bundle-id"))' "${json}" 2>/dev/null | sed 's/^/    /' || true
  grep -q 'apf.nvidia.com/bundle-id' "${json}" && grep -q 'apf.nvidia.com/provenance-token' "${json}"
}

# 5. The gateway log records the sandbox admission evaluation (OpenShell logs
# it as a gateway interceptor evaluation).
gateway_log_has_evaluation() {
  local deadline=$(( $(date +%s) + 60 ))
  local line
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    line="$(save_gateway_log | grep 'gateway interceptor evaluated' | grep 'interceptor=apf/policy-adapter' | tail -n 1 || true)"
    if [[ -n "${line}" ]]; then
      echo "  ${line##*gateway_interceptors::runtime: }"
      return 0
    fi
    sleep 3
  done
  log "gateway log saved to ${LOG_DIR}/openshell-gateway.log"
  return 1
}

# 6. The sandbox admission audit log records the policy injection.
audit_has_injection() {
  local deadline=$(( $(date +%s) + 60 )) tail_out
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    tail_out="$(kctl -n "${APF_NS}" exec "deployment/${APF_FULLNAME}" -c policy-gateway -- tail -n 200 "${AUDIT_FILE}" 2>/dev/null || true)"
    if grep -q 'interceptor.policy_injected' <<<"${tail_out}"; then
      printf '%s\n' "${tail_out}" >"${LOG_DIR}/interceptor-audit.tail.jsonl"
      return 0
    fi
    sleep 3
  done
  printf '%s\n' "${tail_out}" >"${LOG_DIR}/interceptor-audit.tail.jsonl"
  return 1
}

# 7. The pip-stub sidecar is Ready and answers on the pod's loopback.
pip_stub_reachable() {
  local ready code url="http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}"
  ready="$(kctl -n "${APF_NS}" get pods -l "app.kubernetes.io/instance=${APF_RELEASE}" \
    -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="pip-stub")].ready}' 2>/dev/null || true)"
  [[ "${ready}" == true ]] || { log "pip-stub container is not ready"; return 1; }
  code="$(kctl -n "${APF_NS}" exec "deployment/${APF_FULLNAME}" -c policy-service -- \
    /usr/bin/curl -s -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || true)"
  [[ "${code}" == 200 ]]
}

banner "smoke checks"
check "APF deployment ${APF_NS}/${APF_FULLNAME} Ready" apf_ready
check "policy-service verified the signed bundle materials.sh built (digest matches)" bundle_verified_by_pap
check "sandbox admission and egress request policy registered: gateway.toml names apf/policy-adapter and apf-content-policy and the gateway is Ready" gateway_registered_apf
check "openshell gateway info through port-forward ${GATEWAY_LOCAL}" gateway_info
check "sandbox admission: sandbox ${SANDBOX_NAME} created with apf.nvidia.com/bundle-id and provenance-token annotations" sandbox_annotations
check "sandbox admission: OpenShell gateway log records an interceptor evaluation for apf/policy-adapter" gateway_log_has_evaluation
check "sandbox admission: audit log contains interceptor.policy_injected" audit_has_injection
if [[ "${PIP_ENABLED}" == 1 ]]; then
  check "pip-stub sidecar Ready and GET http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH} returns 200 inside the APF pod" pip_stub_reachable
else
  log "PIP disabled; pip-stub check skipped"
fi

if [[ "${FAILED}" == 1 ]]; then
  printf '\n%ssmoke checks failed; logs in %s%s\n' "${C_RED}" "${LOG_DIR}" "${C_RESET}" >&2
  exit 1
fi
ok "all smoke checks passed"
