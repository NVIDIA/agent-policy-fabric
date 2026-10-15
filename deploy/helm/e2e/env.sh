# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Shared variables and helpers for the APF chart verification harness.
# Source this file; every value can be overridden from the environment.
# Defaults stay inside this repository so the harness runs from a clone of apf
# alone; a demo composes it by pointing the knobs below at its own material.

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(cd "${E2E_DIR}/../apf" && pwd)"
APF_DIR="$(cd "${E2E_DIR}/../../.." && pwd)"

KIND_CLUSTER="${KIND_CLUSTER:-apf-e2e}"
KIND_CONTEXT="${KIND_CONTEXT:-kind-${KIND_CLUSTER}}"
OPENSHELL_NS="${OPENSHELL_NS:-openshell}"
APF_NS="${APF_NS:-apf}"
OPENSHELL_RELEASE="${OPENSHELL_RELEASE:-openshell}"
APF_RELEASE="${APF_RELEASE:-apf}"
APF_FULLNAME="${APF_FULLNAME:-apf}"

OPENSHELL_CHART="${OPENSHELL_CHART:-oci://ghcr.io/nvidia/openshell/helm-chart}"
OPENSHELL_VERSION="${OPENSHELL_VERSION:-0.1.3}"
OPENSHELL_IMAGE_TAG="${OPENSHELL_IMAGE_TAG:-0.1.3}"
OPENSHELL_IMAGE_REGISTRY="${OPENSHELL_IMAGE_REGISTRY:-ghcr.io/nvidia/openshell}"
OPENSHELL_SERVICE_PORT="${OPENSHELL_SERVICE_PORT:-8080}"
APF_IMAGE_TAG="${APF_IMAGE_TAG:-dev}"
# Listener ports: sandbox admission (OpenShell gateway interceptor) and egress
# request policy (OpenShell supervisor middleware); chart defaults.
APF_ADMISSION_PORT="${APF_ADMISSION_PORT:-18081}"
APF_EGRESS_PORT="${APF_EGRESS_PORT:-9099}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-nvcr.io/nvidia/base/ubuntu:24.04}"
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v1.0.3}"

E2E_WORK="${E2E_WORK:-${E2E_DIR}/.work}"

# The policy bundle source: a directory holding one *.template.yaml and the
# member files it lists. Revision 2 bumps policy_revision; BUNDLE_V2_TRANSFORM
# may name an executable that receives the staged directory and edits members
# before signing.
BUNDLE_SRC="${BUNDLE_SRC:-${APF_DIR}/examples/demo-bundle}"
BUNDLE_V2_TRANSFORM="${BUNDLE_V2_TRANSFORM:-}"

# Policy information provider lane, off unless PIP_CONFIG_SRC names a
# registration (the in-repo fixture is fixtures/pip/pips.yaml). The stub
# script is served from the pod's loopback by a sidecar; it must accept
# --port and answer PIP_STUB_HEALTH_PATH with 200.
PIP_CONFIG_SRC="${PIP_CONFIG_SRC:-}"
PIP_STUB_SRC="${PIP_STUB_SRC:-${E2E_DIR}/fixtures/pip/stub.py}"
PIP_STUB_IMAGE="${PIP_STUB_IMAGE:-python:3.12-slim}"
PIP_STUB_PORT="${PIP_STUB_PORT:-19500}"
PIP_STUB_HEALTH_PATH="${PIP_STUB_HEALTH_PATH:-/healthz}"
PIP_ENABLED=0
[[ -n "${PIP_CONFIG_SRC}" ]] && PIP_ENABLED=1

# The OpenShell release whose protos the APF binaries were generated from, read
# from the pin in crates/apf-proto/build.rs (the comment after the commit).
APF_OPENSHELL_PIN="$(sed -n 's/^const OPENSHELL_COMMIT.*\/\/ *v\{0,1\}\([0-9][0-9.]*\).*/\1/p' "${APF_DIR}/crates/apf-proto/build.rs" 2>/dev/null | head -n 1)"

DEV_KEYS_DIR="${DEV_KEYS_DIR:-${APF_DIR}/examples/dev-keys}"
SIGNING_KEY_ID="${SIGNING_KEY_ID:-apf-dev}"
APF_COMPILE="${APF_COMPILE:-${APF_DIR}/target/release/apf-compile}"

# The OpenShell CLI: a binary in the work directory wins, else `openshell` on PATH.
if [[ -z "${OPENSHELL_CLI:-}" ]]; then
  OPENSHELL_CLI="openshell"
  [[ -x "${E2E_WORK}/openshell" ]] && OPENSHELL_CLI="${E2E_WORK}/openshell"
fi

# Derived names used by the values files and the materials. The audiences are
# OpenShell's extension-JWT strings: interceptor for sandbox admission,
# middleware for egress request policy.
APF_SERVICE_HOST="${APF_FULLNAME}.${APF_NS}.svc.cluster.local"
OPENSHELL_GATEWAY_ID="${OPENSHELL_GATEWAY_ID:-${OPENSHELL_RELEASE}}"
OPENSHELL_JWT_ISSUER="openshell-gateway:${OPENSHELL_GATEWAY_ID}"
INTERCEPTOR_AUDIENCE="urn:openshell:extension:interceptor:${OPENSHELL_GATEWAY_ID}"
MIDDLEWARE_AUDIENCE="urn:openshell:extension:middleware:${OPENSHELL_GATEWAY_ID}"
OPENSHELL_JWT_SECRET="${OPENSHELL_JWT_SECRET:-${OPENSHELL_RELEASE}-jwt-keys}"
OPENSHELL_SERVICE="${OPENSHELL_SERVICE:-${OPENSHELL_RELEASE}}"
OPENSHELL_GATEWAY_URL="http://${OPENSHELL_SERVICE}.${OPENSHELL_NS}.svc.cluster.local:${OPENSHELL_SERVICE_PORT}"

export E2E_DIR CHART_DIR APF_DIR KIND_CLUSTER KIND_CONTEXT OPENSHELL_NS APF_NS \
  OPENSHELL_RELEASE APF_RELEASE APF_FULLNAME OPENSHELL_CHART OPENSHELL_VERSION OPENSHELL_IMAGE_TAG \
  OPENSHELL_IMAGE_REGISTRY OPENSHELL_SERVICE_PORT APF_IMAGE_TAG APF_ADMISSION_PORT APF_EGRESS_PORT \
  SANDBOX_IMAGE AGENT_SANDBOX_VERSION E2E_WORK BUNDLE_SRC BUNDLE_V2_TRANSFORM PIP_CONFIG_SRC \
  PIP_STUB_SRC PIP_STUB_IMAGE PIP_STUB_PORT PIP_STUB_HEALTH_PATH PIP_ENABLED APF_OPENSHELL_PIN \
  DEV_KEYS_DIR SIGNING_KEY_ID APF_COMPILE OPENSHELL_CLI \
  APF_SERVICE_HOST OPENSHELL_GATEWAY_ID OPENSHELL_JWT_ISSUER INTERCEPTOR_AUDIENCE MIDDLEWARE_AUDIENCE \
  OPENSHELL_JWT_SECRET OPENSHELL_SERVICE OPENSHELL_GATEWAY_URL

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

kctl() { kubectl --context "${KIND_CONTEXT}" "$@"; }
helmk() { helm --kube-context "${KIND_CONTEXT}" "$@"; }

# wait_for_rollout <namespace> <kind/name> [timeout]
wait_for_rollout() {
  local ns="$1" target="$2" timeout="${3:-300s}"
  kctl -n "${ns}" rollout status "${target}" --timeout="${timeout}"
}

# Prints the pods in all namespaces and the logs of every pod that is not Running/Succeeded
# in the harness namespaces. Called by steps that fail.
dump_cluster_state() {
  echo "--- kubectl get pods -A" >&2
  kctl get pods -A -o wide >&2 || true
  local ns pod
  for ns in "${OPENSHELL_NS}" "${APF_NS}"; do
    for pod in $(kctl -n "${ns}" get pods -o jsonpath='{range .items[?(@.status.phase!="Running")]}{.metadata.name}{"\n"}{end}' 2>/dev/null); do
      echo "--- describe ${ns}/${pod}" >&2
      kctl -n "${ns}" describe pod "${pod}" 2>&1 | tail -40 >&2 || true
      echo "--- logs ${ns}/${pod} (all containers)" >&2
      kctl -n "${ns}" logs "${pod}" --all-containers --tail=80 >&2 || true
    done
    for pod in $(kctl -n "${ns}" get pods -o jsonpath='{range .items[?(@.status.containerStatuses[*].ready==false)]}{.metadata.name}{"\n"}{end}' 2>/dev/null); do
      echo "--- logs ${ns}/${pod} (not ready)" >&2
      kctl -n "${ns}" logs "${pod}" --all-containers --tail=80 >&2 || true
    done
  done
}
