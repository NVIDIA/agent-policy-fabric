# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Kind environment: the knobs of the chart deployment on a kind cluster and
# the dispatch functions suites reach through e2e/support/env.sh. Sourced
# after common.sh. Every value can be overridden from the environment;
# e2e/with-kind-stack.sh exports the run's values before it runs a command.

CHART_DIR="${APF_DIR}/deploy/helm/apf"
KIND_CLUSTER="${KIND_CLUSTER:-apf-e2e}"
# The context kind creates for the cluster. Derived, not a knob: teardown
# uninstalls releases and deletes namespaces on this context, so it must not
# name another cluster.
KIND_CONTEXT="kind-${KIND_CLUSTER}"
KIND_NODE="${KIND_CLUSTER}-control-plane"
OPENSHELL_NS="${OPENSHELL_NS:-openshell}"
APF_NS="${APF_NS:-apf}"
OPENSHELL_RELEASE="${OPENSHELL_RELEASE:-openshell}"
APF_RELEASE="${APF_RELEASE:-apf}"
APF_FULLNAME="${APF_FULLNAME:-apf}"
OPENSHELL_CHART="${OPENSHELL_CHART:-oci://ghcr.io/nvidia/openshell/helm-chart}"
OPENSHELL_SERVICE_PORT="${OPENSHELL_SERVICE_PORT:-8080}"
# Local port of the gateway port-forward; 0 lets kubectl pick a free one.
OPENSHELL_LOCAL_PORT="${OPENSHELL_LOCAL_PORT:-0}"
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v1.0.3}"

APF_E2E_ENV=kind
APF_E2E_WORK="${E2E_WORK}/kind"
APF_E2E_LOG_DIR="${APF_E2E_WORK}/logs"
# The chart needs OpenShell's extension-JWT key for its trust profiles, so an
# OpenShell gateway is always part of a kind run.
APF_E2E_OPENSHELL=1
APF_E2E_PIP="${APF_E2E_PIP:-0}"
[[ -n "${PIP_CONFIG_SRC}" ]] && APF_E2E_PIP=1
if [[ "${APF_E2E_PIP}" == 1 && -z "${PIP_CONFIG_SRC}" ]]; then
  PIP_CONFIG_SRC="${E2E_DIR}/configs/pip/pips.yaml"
fi

# Node-side references of the preloaded fixture images, set by the cluster
# step (a digest reference is retagged before it is loaded) and recorded in
# run.env for --existing.
SANDBOX_NODE_IMAGE="${SANDBOX_NODE_IMAGE:-}"
GRPCURL_NODE_IMAGE="${GRPCURL_NODE_IMAGE:-}"
PIP_STUB_NODE_IMAGE="${PIP_STUB_NODE_IMAGE:-}"

# Derived names used by the values files and the materials. The audiences are
# OpenShell's extension-JWT strings: interceptor for sandbox admission,
# middleware for egress request policy.
APF_SERVICE_HOST="${APF_FULLNAME}.${APF_NS}.svc.cluster.local"
OPENSHELL_GATEWAY_ID="${OPENSHELL_GATEWAY_ID:-${OPENSHELL_RELEASE}}"
OPENSHELL_JWT_ISSUER="openshell-gateway:${OPENSHELL_GATEWAY_ID}"
OPENSHELL_JWT_SECRET="${OPENSHELL_JWT_SECRET:-${OPENSHELL_RELEASE}-jwt-keys}"
OPENSHELL_SERVICE="${OPENSHELL_SERVICE:-${OPENSHELL_RELEASE}}"
OPENSHELL_GATEWAY_URL="http://${OPENSHELL_SERVICE}.${OPENSHELL_NS}.svc.cluster.local:${OPENSHELL_SERVICE_PORT}"

# The knobs a run is rendered with, recorded in APF_E2E_WORK/run.env.
KIND_RUN_KNOBS="KIND_CLUSTER OPENSHELL_NS APF_NS OPENSHELL_RELEASE APF_RELEASE APF_FULLNAME
  OPENSHELL_CHART OPENSHELL_VERSION OPENSHELL_IMAGE_TAG OPENSHELL_IMAGE_REGISTRY OPENSHELL_SERVICE_PORT
  OPENSHELL_LOCAL_PORT AGENT_SANDBOX_VERSION APF_IMAGE_TAG APF_ADMISSION_PORT APF_EGRESS_PORT SANDBOX_IMAGE
  GRPCURL_IMAGE SANDBOX_NODE_IMAGE GRPCURL_NODE_IMAGE PIP_STUB_NODE_IMAGE OPENSHELL_CLI OPENSHELL_GATEWAY_ID
  APF_KEY_ID SIGNING_KEY_ID DEV_KEYS_DIR APF_COMPILE BUNDLE_SRC BUNDLE_V2_TRANSFORM PIP_CONFIG_SRC PIP_STUB_SRC
  PIP_STUB_IMAGE PIP_STUB_PORT PIP_STUB_HEALTH_PATH APF_E2E_PIP"

export CHART_DIR KIND_CLUSTER KIND_CONTEXT KIND_NODE OPENSHELL_NS APF_NS OPENSHELL_RELEASE APF_RELEASE \
  APF_FULLNAME OPENSHELL_CHART OPENSHELL_SERVICE_PORT OPENSHELL_LOCAL_PORT AGENT_SANDBOX_VERSION \
  APF_E2E_ENV APF_E2E_WORK APF_E2E_LOG_DIR APF_E2E_OPENSHELL APF_E2E_PIP PIP_CONFIG_SRC \
  SANDBOX_NODE_IMAGE GRPCURL_NODE_IMAGE PIP_STUB_NODE_IMAGE APF_SERVICE_HOST OPENSHELL_GATEWAY_ID \
  OPENSHELL_JWT_ISSUER OPENSHELL_JWT_SECRET OPENSHELL_SERVICE OPENSHELL_GATEWAY_URL

kctl() { kubectl --context "${KIND_CONTEXT}" "$@"; }
helmk() { helm --kube-context "${KIND_CONTEXT}" "$@"; }

# wait_for_rollout <namespace> <kind/name> [timeout]
wait_for_rollout() {
  local ns="$1" target="$2" timeout="${3:-300s}"
  kctl -n "${ns}" rollout status "${target}" --timeout="${timeout}"
}

# apf_pod: the name of the APF release's live pod; a pod being replaced
# (deletion timestamp set) is skipped.
apf_pod() {
  local name deleting
  while read -r name deleting; do
    [[ -n "${name}" && -z "${deleting}" ]] || continue
    printf '%s' "${name}"
    return 0
  done < <(kctl -n "${APF_NS}" get pod -l "app.kubernetes.io/instance=${APF_RELEASE}" \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.deletionTimestamp}{"\n"}{end}' 2>/dev/null || true)
  return 1
}

# Component mapping: the APF components are containers of the APF Deployment,
# the OpenShell gateway is the StatefulSet of the OpenShell release.
component_ns() {
  case "$1" in
    openshell-gateway) printf '%s' "${OPENSHELL_NS}" ;;
    *) printf '%s' "${APF_NS}" ;;
  esac
}
component_workload() {
  case "$1" in
    openshell-gateway) printf 'statefulset/%s' "${OPENSHELL_RELEASE}" ;;
    *) printf 'deployment/%s' "${APF_FULLNAME}" ;;
  esac
}
component_container() {
  case "$1" in
    openshell-gateway) printf 'openshell-gateway' ;;
    *) printf '%s' "$1" ;;
  esac
}
component_selector() {
  case "$1" in
    openshell-gateway) printf 'app.kubernetes.io/name=openshell,app.kubernetes.io/instance=%s' "${OPENSHELL_RELEASE}" ;;
    *) printf 'app.kubernetes.io/instance=%s' "${APF_RELEASE}" ;;
  esac
}

# apf_e2e_ready <component>: the container reports ready on its pod.
apf_e2e_ready() {
  local ready
  ready="$(kctl -n "$(component_ns "$1")" get pod -l "$(component_selector "$1")" \
    -o jsonpath="{.items[0].status.containerStatuses[?(@.name==\"$(component_container "$1")\")].ready}" 2>/dev/null || true)"
  [[ "${ready}" == true ]]
}

apf_e2e_logs() {
  kctl -n "$(component_ns "$1")" logs "$(component_workload "$1")" -c "$(component_container "$1")" --tail=-1 2>/dev/null | strip_ansi
}

apf_e2e_exec() {
  local component="$1"
  shift
  kctl -n "$(component_ns "${component}")" exec "$(component_workload "${component}")" -c "$(component_container "${component}")" -- "$@"
}

apf_e2e_audit_tail() {
  apf_e2e_exec "$1" tail -n "$3" "/var/log/apf/audit/$2"
}

kind_node_has_image() { docker exec "${KIND_NODE}" crictl inspecti "$1" >/dev/null 2>&1; }

ephemeral_exit_code() {
  kctl -n "${APF_NS}" get pod "$1" -o jsonpath="{.status.ephemeralContainerStatuses[?(@.name==\"$2\")].state.terminated.exitCode}" 2>/dev/null || true
}
ephemeral_terminated() { [[ -n "$(ephemeral_exit_code "$1" "$2")" ]]; }

# apf_e2e_evaluate <request.json>: sends the EvaluateRequest over the gateway
# socket from an ephemeral grpcurl container in the APF pod (kubectl debug
# with the custom profile under e2e/configs/kind), running as 65532 with the
# socket volume and the proto ConfigMap mounted. The request travels as an
# argument and the response is read from the container's log once it
# terminated. Ephemeral containers are immutable, so each call gets a new
# name; terminated ones stay listed in the pod until its next restart.
# Returns 2 when this pod or cluster cannot take the container: the pod lacks
# the volumes the harness values add, or the API refuses ephemeral containers
# or the custom profile. Any other failure returns 1 with the reason.
apf_e2e_evaluate() {
  local request="$1" pod name out code err volumes v seq
  [[ -f "${request}" ]] || { echo "request file not found: ${request}" >&2; return 1; }
  pod="$(apf_pod)" || { echo "no pod of release ${APF_RELEASE} in namespace ${APF_NS}" >&2; return 1; }
  volumes="$(kctl -n "${APF_NS}" get pod "${pod}" -o jsonpath='{range .spec.volumes[*]}{.name}{"\n"}{end}' 2>/dev/null || true)"
  for v in gateway-socket evaluate-proto; do
    grep -qx "${v}" <<<"${volumes}" || { echo "pod ${pod} has no volume ${v}; the release was installed without the values e2e/with-kind-stack.sh renders (the evaluate-proto volume carries the protos)" >&2; return 2; }
  done
  [[ -n "${GRPCURL_NODE_IMAGE}" ]] || { echo "GRPCURL_NODE_IMAGE is unset; the wrapper preloads the grpcurl image and records its node-side reference" >&2; return 1; }
  kind_node_has_image "${GRPCURL_NODE_IMAGE}" || { echo "grpcurl image ${GRPCURL_NODE_IMAGE} is not in node ${KIND_NODE}; a run of e2e/with-kind-stack.sh preloads it" >&2; return 1; }
  # The name must be new for this pod: the sequence is the count of ephemeral
  # containers it already has, which a caller running in a subshell cannot
  # lose track of.
  seq="$(kctl -n "${APF_NS}" get pod "${pod}" -o jsonpath='{.spec.ephemeralContainers[*].name}' 2>/dev/null | wc -w | tr -d ' ')"
  name="apf-e2e-evaluate-$$-${RANDOM}-$(( seq + 1 ))"
  err="$(mktemp "${TMPDIR:-/tmp}/apf-evaluate.XXXXXX")"
  if ! kctl -n "${APF_NS}" debug "pod/${pod}" -q --attach=false --container "${name}" \
      --image "${GRPCURL_NODE_IMAGE}" --image-pull-policy Never \
      --profile restricted --custom "${E2E_DIR}/configs/kind/evaluate-debug-profile.yaml" \
      --arguments-only -- -plaintext -import-path /proto \
      -proto nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto \
      -d "$(cat "${request}")" unix:///run/apf-gateway/sock/policy-gateway.sock \
      nvidia.agent_policy_fabric.pdp.v1alpha1.EvaluationService/Evaluate >/dev/null 2>"${err}"; then
    cat "${err}" >&2
    # Refusals of the mechanism itself mean "unsupported here"; a rejected
    # name or any other error is a failure.
    if ! grep -qiE 'duplicate|already exists' "${err}" \
      && grep -qiE 'custom profile|ephemeralcontainers|forbidden|admission webhook|not supported|unknown flag' "${err}"; then
      rm -f "${err}"
      return 2
    fi
    rm -f "${err}"
    return 1
  fi
  rm -f "${err}"
  if ! wait_until 60 ephemeral_terminated "${pod}" "${name}"; then
    echo "ephemeral container ${name} did not terminate within 60s" >&2
    kctl -n "${APF_NS}" get pod "${pod}" \
      -o jsonpath="{range .status.ephemeralContainerStatuses[?(@.name==\"${name}\")]}waiting: {.state.waiting.reason} {.state.waiting.message}{'\n'}running since: {.state.running.startedAt}{'\n'}{end}" 2>/dev/null >&2 || true
    kctl -n "${APF_NS}" describe pod "${pod}" 2>/dev/null | tail -n 20 >&2 || true
    return 1
  fi
  out="$(kctl -n "${APF_NS}" logs "pod/${pod}" -c "${name}" 2>&1)" || { printf '%s\n' "${out}" >&2; return 1; }
  code="$(ephemeral_exit_code "${pod}" "${name}")"
  [[ "${code}" == 0 ]] || { printf 'grpcurl exited %s:\n%s\n' "${code}" "${out}" >&2; return 1; }
  printf '%s\n' "${out}"
}

# Prints the pods in all namespaces and the logs of every pod that is not
# Running or not ready in the harness namespaces.
apf_e2e_dump_state() {
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
