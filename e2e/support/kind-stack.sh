# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Kind lifecycle, sourced by e2e/with-kind-stack.sh after common.sh,
# env-kind.sh, materials.sh, openshell.sh and kind-cluster.sh: preflight, the
# OpenShell install, the materials and their delivery as Secrets and
# ConfigMaps, the APF install, the registration upgrade, the port-forwards
# and teardown. Every step is safe to rerun.

TLS_DIR="${APF_E2E_WORK}/tls"
TLS_CRT="${TLS_DIR}/apf.crt"
TLS_KEY="${TLS_DIR}/apf.key"
JWT_PUB="${APF_E2E_WORK}/openshell-jwt-public.pem"
JWT_KID_FILE="${APF_E2E_WORK}/openshell-jwt-kid"
TRUST_INTERCEPTOR="${APF_E2E_WORK}/trust-interceptor.toml"
TRUST_MIDDLEWARE="${APF_E2E_WORK}/trust-middleware.toml"
HTTP_TOKEN="${APF_E2E_WORK}/http-bearer-token"
PIP_RENDERED="${APF_E2E_WORK}/pips.yaml"
VALUES_DIR="${APF_E2E_WORK}/values"
PROTO_DIR="${APF_DIR}/contracts/proto/nvidia/agent_policy_fabric"
# Present between the materials and the APF install when the signed document
# changed since the previous run.
BUNDLE_CHANGED_MARK="${APF_E2E_WORK}/bundle-v1.changed"
# The port-forwards of the current run, so an interrupted run's leftovers can
# be ended by the next one.
PF_PIDS_FILE="${APF_E2E_WORK}/port-forward.pids"
PF_GATEWAY_PID=""
PF_HEALTH_PID=""
GATEWAY_LOCAL_PORT=""
HEALTH_LOCAL_PORT=""

kind_preflight() {
  require_cmd kind kubectl helm yq docker openssl python3 tar shasum curl
  docker info >/dev/null 2>&1 || fail "docker daemon not reachable"
  [[ "${APF_IMAGE_TAG}" != latest ]] || fail "APF_IMAGE_TAG=latest is refused; pin a tag"
  [[ "${OPENSHELL_IMAGE_TAG}" != latest ]] || fail "OPENSHELL_IMAGE_TAG=latest is refused; pin a tag"
  local image
  for image in "apf-policy-service:${APF_IMAGE_TAG}" "apf-policy-gateway:${APF_IMAGE_TAG}"; do
    docker image inspect "${image}" >/dev/null 2>&1 || fail "image ${image} not found; build it first (e2e/README.md, prerequisites)"
  done
  [[ -f "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" ]] || fail "signing seed missing: ${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed"
  [[ -f "${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub" ]] || fail "trust key missing: ${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub"
  [[ -d "${BUNDLE_SRC}" ]] || fail "BUNDLE_SRC not found: ${BUNDLE_SRC}"
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    [[ -f "${PIP_CONFIG_SRC}" ]] || fail "PIP_CONFIG_SRC not found: ${PIP_CONFIG_SRC}"
    [[ -f "${PIP_STUB_SRC}" ]] || fail "PIP_STUB_SRC not found: ${PIP_STUB_SRC}"
  fi
  openshell_cli_ensure "${OPENSHELL_VERSION}"
  ok "preflight passed"
}

# helm_recover <release> <namespace>: an interrupted helm operation leaves
# the release pending and blocks the next one. A pending install is
# uninstalled; a pending upgrade or rollback is rolled back to the last
# deployed revision, or uninstalled when there is none.
helm_recover() {
  local release="$1" ns="$2" status revision
  status="$(helmk status "${release}" -n "${ns}" -o json 2>/dev/null | yq -p json '.info.status' 2>/dev/null || true)"
  case "${status}" in
    pending-install)
      log "release ${ns}/${release} is ${status}; uninstalling the interrupted install"
      helmk uninstall "${release}" -n "${ns}" --no-hooks --wait --timeout 5m
      ;;
    pending-upgrade|pending-rollback)
      revision="$(helmk history "${release}" -n "${ns}" -o json 2>/dev/null \
        | yq -p json '([.[] | select(.status == "deployed")] | select(length > 0) | .[-1].revision) // ([.[] | select(.status == "superseded")] | select(length > 0) | .[-1].revision)' 2>/dev/null || true)"
      if [[ -n "${revision}" && "${revision}" != null ]]; then
        log "release ${ns}/${release} is ${status}; rolling back to revision ${revision}"
        helmk rollback "${release}" "${revision}" -n "${ns}" --wait --timeout 5m
      else
        log "release ${ns}/${release} is ${status} with no deployed revision; uninstalling"
        helmk uninstall "${release}" -n "${ns}" --no-hooks --wait --timeout 5m
      fi
      ;;
  esac
}

read_openshell_jwt() {
  local pem kid
  kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" >/dev/null 2>&1 \
    || fail "Secret ${OPENSHELL_NS}/${OPENSHELL_JWT_SECRET} not found; the OpenShell install creates it"
  pem="$(kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" -o 'jsonpath={.data.public\.pem}' | base64 --decode)"
  kid="$(kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" -o 'jsonpath={.data.kid}' | base64 --decode | tr -d '\r\n')"
  [[ "${pem}" == *"BEGIN PUBLIC KEY"* ]] || fail "Secret ${OPENSHELL_JWT_SECRET} key public.pem is not a PEM public key"
  [[ -n "${kid}" ]] || fail "Secret ${OPENSHELL_JWT_SECRET} key kid is empty"
  printf '%s\n' "${pem}" >"${JWT_PUB}"
  printf '%s\n' "${kid}" >"${JWT_KID_FILE}"
  ok "OpenShell JWT public key (kid ${kid}) read from ${OPENSHELL_NS}/${OPENSHELL_JWT_SECRET}"
}

# The volume the evaluate check mounts into its ephemeral grpcurl container:
# the two proto files from ConfigMap apf-evaluate-proto laid out as import
# paths. Helm replaces lists, so it is appended to every rendered APF values
# file.
PROTO_VOLUME='{"name": "evaluate-proto", "configMap": {"name": "apf-evaluate-proto", "items": [{"key": "pdp.proto", "path": "nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto"}, {"key": "runtime.proto", "path": "nvidia/agent_policy_fabric/runtime/v1alpha1/runtime.proto"}]}}'
export PROTO_VOLUME

# render_values: the checked-in values assume the default names; rewrite them
# from the environment into VALUES_DIR so the knobs (namespaces, tags, ports,
# preloaded images) take effect.
render_values() {
  mkdir -p "${VALUES_DIR}"
  local sandbox_ref="${SANDBOX_NODE_IMAGE:-${SANDBOX_IMAGE}}" sandbox_repo sandbox_tag
  sandbox_repo="$(image_repository "${sandbox_ref}")"
  sandbox_tag="$(image_tag "${sandbox_ref}")"
  [[ -n "${sandbox_tag}" ]] || fail "the sandbox image must be in the node under a tag; got ${sandbox_ref}"
  OS_TAG="${OPENSHELL_IMAGE_TAG}" SANDBOX_REPO="${sandbox_repo}" SANDBOX_TAG="${sandbox_tag}" \
    yq '.global.image.tag = strenv(OS_TAG)
        | .sandbox.image.repository = strenv(SANDBOX_REPO)
        | .sandbox.image.tag = strenv(SANDBOX_TAG)
        | del(.sandbox.image.digest)' \
    "${E2E_DIR}/configs/kind/openshell-values.yaml" >"${VALUES_DIR}/openshell-values.yaml"

  # The stanza keys are OpenShell's: sandbox admission registers under
  # openshell.gateway.interceptors, egress request policy under
  # openshell.supervisor.middleware.
  ADMISSION_ENDPOINT="https://${APF_SERVICE_HOST}:${APF_ADMISSION_PORT}" \
  EGRESS_ENDPOINT="https://${APF_SERVICE_HOST}:${APF_EGRESS_PORT}" \
  INTERCEPTOR_AUDIENCE="urn:openshell:extension:interceptor:${OPENSHELL_GATEWAY_ID}" \
  MIDDLEWARE_AUDIENCE="urn:openshell:extension:middleware:${OPENSHELL_GATEWAY_ID}" \
    yq '.gatewayConfig["openshell.gateway.interceptors"][0].grpc_endpoint = strenv(ADMISSION_ENDPOINT)
        | .gatewayConfig["openshell.gateway.interceptors"][0].audience = strenv(INTERCEPTOR_AUDIENCE)
        | .gatewayConfig["openshell.supervisor.middleware"][0].grpc_endpoint = strenv(EGRESS_ENDPOINT)
        | .gatewayConfig["openshell.supervisor.middleware"][0].audience = strenv(MIDDLEWARE_AUDIENCE)' \
    "${E2E_DIR}/configs/kind/openshell-values-apf.yaml" >"${VALUES_DIR}/openshell-values-apf.yaml"

  yq '.fullnameOverride = strenv(APF_FULLNAME)
      | .policyService.image.tag = strenv(APF_IMAGE_TAG)
      | .policyGateway.image.tag = strenv(APF_IMAGE_TAG)
      | .policyGateway.openshell.gatewayEndpoint = strenv(OPENSHELL_GATEWAY_URL)
      | .policyGateway.openshell.admission.port = env(APF_ADMISSION_PORT)
      | .policyGateway.openshell.egress.port = env(APF_EGRESS_PORT)
      | .extraVolumes += [env(PROTO_VOLUME)]' \
    "${E2E_DIR}/configs/kind/apf-values.yaml" >"${VALUES_DIR}/apf-values.yaml"

  PIP_STUB_NODE_REF="${PIP_STUB_NODE_IMAGE:-${PIP_STUB_IMAGE}}" \
  PIP_STUB_HEALTH_URL="http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}" \
    yq '.extraContainers[0].image = strenv(PIP_STUB_NODE_REF)
        | .extraContainers[0].command[3] = strenv(PIP_STUB_PORT)
        | (.extraContainers[0].env[] | select(.name == "PIP_STUB_HEALTH_URL")).value = strenv(PIP_STUB_HEALTH_URL)
        | .extraVolumes += [env(PROTO_VOLUME)]' \
    "${E2E_DIR}/configs/kind/apf-values-pip.yaml" >"${VALUES_DIR}/apf-values-pip.yaml"
  ok "values rendered into ${VALUES_DIR}"
}

jwt_secret_present() { kctl -n "${OPENSHELL_NS}" get secret "${OPENSHELL_JWT_SECRET}" >/dev/null 2>&1; }

# OpenShell without extensions; its certgen Job writes the extension-JWT
# Secret the APF trust profiles are built from.
kind_openshell_plain() {
  render_values
  helm_recover "${OPENSHELL_RELEASE}" "${OPENSHELL_NS}"
  helmk upgrade --install "${OPENSHELL_RELEASE}" "${OPENSHELL_CHART}" --version "${OPENSHELL_VERSION}" \
    --namespace "${OPENSHELL_NS}" --create-namespace \
    --values "${VALUES_DIR}/openshell-values.yaml" \
    --wait --timeout 10m
  wait_for_rollout "${OPENSHELL_NS}" "statefulset/${OPENSHELL_RELEASE}" 300s
  wait_until 120 jwt_secret_present || fail "Secret ${OPENSHELL_NS}/${OPENSHELL_JWT_SECRET} not found after the OpenShell install"
  ok "OpenShell ${OPENSHELL_VERSION} installed without extensions"
}

apply_bundle() {
  local rev="$1" tarball
  tarball="${APF_E2E_WORK}/bundle-${rev}.tar.gz"
  [[ -f "${tarball}" ]] || stage_bundle "${rev}"
  kctl -n "${APF_NS}" create configmap apf-bundle --from-file="bundle.tar.gz=${tarball}" \
    --dry-run=client -o yaml | kctl apply -f -
  ok "ConfigMap ${APF_NS}/apf-bundle holds bundle ${rev}"
}

apply_apf_materials() {
  kctl create namespace "${APF_NS}" --dry-run=client -o yaml | kctl apply -f -
  ensure_http_token "${HTTP_TOKEN}"
  kctl -n "${APF_NS}" create secret generic apf-runtime \
    --from-file="document-signing.seed=${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.seed" \
    --from-file="token=${HTTP_TOKEN}" \
    --from-file="tls.crt=${TLS_CRT}" \
    --from-file="tls.key=${TLS_KEY}" \
    --from-file="trust.toml=${TRUST_INTERCEPTOR}" \
    --dry-run=client -o yaml | kctl apply -f -
  kctl -n "${APF_NS}" create secret generic apf-egress \
    --from-file="tls.crt=${TLS_CRT}" \
    --from-file="tls.key=${TLS_KEY}" \
    --from-file="trust.toml=${TRUST_MIDDLEWARE}" \
    --dry-run=client -o yaml | kctl apply -f -
  kctl -n "${APF_NS}" create configmap apf-trust \
    --from-file="${SIGNING_KEY_ID}.pub=${DEV_KEYS_DIR}/${SIGNING_KEY_ID}.pub" \
    --dry-run=client -o yaml | kctl apply -f -
  # The protos the evaluate check's grpcurl needs; pdp.proto imports runtime.proto.
  kctl -n "${APF_NS}" create configmap apf-evaluate-proto \
    --from-file="pdp.proto=${PROTO_DIR}/pdp/v1alpha1/pdp.proto" \
    --from-file="runtime.proto=${PROTO_DIR}/runtime/v1alpha1/runtime.proto" \
    --dry-run=client -o yaml | kctl apply -f -
  apply_bundle v1
  kctl -n "${OPENSHELL_NS}" create configmap apf-ca --from-file="ca.crt=${TLS_CRT}" \
    --dry-run=client -o yaml | kctl apply -f -
  ok "Secrets apf-runtime, apf-egress and ConfigMaps apf-trust, apf-bundle, apf-evaluate-proto (${APF_NS}), apf-ca (${OPENSHELL_NS}) applied"
}

apply_pip_materials() {
  [[ -f "${PIP_CONFIG_SRC}" ]] || fail "PIP_CONFIG_SRC not found: ${PIP_CONFIG_SRC}"
  [[ -f "${PIP_STUB_SRC}" ]] || fail "PIP_STUB_SRC not found: ${PIP_STUB_SRC}"
  # The provider behind the registration runs as a sidecar in the APF pod, so
  # the registration's loopback URLs are used as written.
  cp "${PIP_CONFIG_SRC}" "${PIP_RENDERED}"
  kctl -n "${APF_NS}" create configmap apf-pip --from-file="pips.yaml=${PIP_RENDERED}" \
    --dry-run=client -o yaml | kctl apply -f -
  kctl -n "${APF_NS}" create configmap apf-pip-stub --from-file="stub.py=${PIP_STUB_SRC}" \
    --dry-run=client -o yaml | kctl apply -f -
  ok "ConfigMaps apf-pip and apf-pip-stub applied (provider on 127.0.0.1:${PIP_STUB_PORT}, served by the pip-stub sidecar)"
}

# Materials: both signed bundle revisions, the serving certificate with the
# Service DNS names, the trust profiles from OpenShell's JWT Secret, and the
# Secrets and ConfigMaps the chart expects.
kind_materials() {
  mkdir -p "${APF_E2E_WORK}" "${TLS_DIR}"
  log "bundle source: ${BUNDLE_SRC}"
  ensure_compile
  local previous=""
  [[ -f "${APF_E2E_WORK}/bundle-v1.digest" ]] && previous="$(cat "${APF_E2E_WORK}/bundle-v1.digest")"
  stage_bundle v1
  stage_bundle v2
  rm -f "${BUNDLE_CHANGED_MARK}"
  if [[ -n "${previous}" && "${previous}" != "$(cat "${APF_E2E_WORK}/bundle-v1.digest")" ]]; then
    log "signed document changed since the previous run"
    : >"${BUNDLE_CHANGED_MARK}"
  fi
  make_cert "${TLS_CRT}" "${TLS_KEY}" "${APF_SERVICE_HOST}" \
    "DNS:${APF_SERVICE_HOST}" "DNS:${APF_FULLNAME}.${APF_NS}.svc" "DNS:${APF_FULLNAME}.${APF_NS}" "DNS:${APF_FULLNAME}"
  read_openshell_jwt
  openshell_trust_profiles "${APF_E2E_WORK}" "${OPENSHELL_JWT_ISSUER}" "${OPENSHELL_GATEWAY_ID}" "${JWT_KID_FILE}" "${JWT_PUB}"
  apply_apf_materials
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    apply_pip_materials
  else
    log "PIP lane off; no apf-pip or apf-pip-stub materials"
  fi
}

# The APF chart. The bundle ConfigMap is not chart-created, so its digest
# goes on the pod as an annotation and the pod rolls exactly when the signed
# document changes. The state PVC of an installed release keeps the
# anti-rollback counter, which refuses a different document at the same
# revision, so a kept release is reinstalled on a fresh state volume when
# the document changes.
install_apf() {
  local extra=()
  [[ "${APF_E2E_PIP}" == 1 ]] && extra=(--values "${VALUES_DIR}/apf-values-pip.yaml")
  helm lint --strict "${CHART_DIR}" --values "${VALUES_DIR}/apf-values.yaml" "${extra[@]+"${extra[@]}"}"
  if [[ -f "${BUNDLE_CHANGED_MARK}" ]] && helmk status "${APF_RELEASE}" -n "${APF_NS}" >/dev/null 2>&1; then
    log "release ${APF_NS}/${APF_RELEASE} is installed and the signed document changed: the state PVC holds the anti-rollback counter of the previous document, which refuses a different document at the same revision; reinstalling on a fresh state volume"
    uninstall_release "${APF_RELEASE}" "${APF_NS}"
    kctl -n "${APF_NS}" delete pvc "${APF_FULLNAME}-state" --ignore-not-found --wait=true
  fi
  rm -f "${BUNDLE_CHANGED_MARK}"
  helm_recover "${APF_RELEASE}" "${APF_NS}"
  helmk upgrade --install "${APF_RELEASE}" "${CHART_DIR}" \
    --namespace "${APF_NS}" --create-namespace \
    --values "${VALUES_DIR}/apf-values.yaml" "${extra[@]+"${extra[@]}"}" \
    --set-string "podAnnotations.apf\.nvidia\.com/bundle-digest=$(cat "${APF_E2E_WORK}/bundle-v1.digest")" \
    --wait --timeout 5m
  wait_for_rollout "${APF_NS}" "deployment/${APF_FULLNAME}" 300s
  ok "APF release ${APF_NS}/${APF_RELEASE} rolled out"
}

# OpenShell again with the registration overlay. The gateway TOML OpenShell
# renders from it is saved as a diagnostic.
register_apf_with_openshell() {
  helm_recover "${OPENSHELL_RELEASE}" "${OPENSHELL_NS}"
  helmk upgrade "${OPENSHELL_RELEASE}" "${OPENSHELL_CHART}" --version "${OPENSHELL_VERSION}" \
    --namespace "${OPENSHELL_NS}" \
    --values "${VALUES_DIR}/openshell-values.yaml" \
    --values "${VALUES_DIR}/openshell-values-apf.yaml" \
    --wait --timeout 10m
  wait_for_rollout "${OPENSHELL_NS}" "statefulset/${OPENSHELL_RELEASE}" 300s
  kctl -n "${OPENSHELL_NS}" get configmap "${OPENSHELL_RELEASE}-config" -o jsonpath='{.data.gateway\.toml}' \
    >"${APF_E2E_LOG_DIR}/openshell-gateway.toml" 2>/dev/null || true
  ok "APF registered with OpenShell; rendered gateway.toml saved to ${APF_E2E_LOG_DIR}/openshell-gateway.toml"
}

forward_port() { sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) ->.*/\1/p' "$1" | head -n 1; }

# forward_wait <log>: until kubectl printed the local port, or it reported an error.
forward_wait() {
  local deadline=$(( $(date +%s) + 60 ))
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    [[ -n "$(forward_port "$1")" ]] && return 0
    grep -qi 'error\|unable to' "$1" 2>/dev/null && return 1
    sleep 0.5
  done
  return 1
}

is_port_forward() { [[ "$(ps -o command= -p "$1" 2>/dev/null || true)" == *kubectl*port-forward* ]]; }
process_gone() { ! kill -0 "$1" 2>/dev/null; }

# kind_forward_release: ends the port-forwards an earlier wrapper left behind
# (their pids are in PF_PIDS_FILE) and removes the file. Safe to call from
# any mode, teardown included.
kind_forward_release() {
  local pid
  [[ -f "${PF_PIDS_FILE}" ]] || return 0
  while read -r pid; do
    [[ -n "${pid}" ]] && is_port_forward "${pid}" || continue
    log "ending port-forward left by an earlier run (pid ${pid})"
    kill "${pid}" 2>/dev/null || true
    wait_until 10 process_gone "${pid}" || true
  done <"${PF_PIDS_FILE}"
  rm -f "${PF_PIDS_FILE}"
}

# kind_forward_free_pinned_port: when the gateway port is pinned, ends a
# kubectl port-forward still holding it. Any other holder is reported with
# the knob that moves the forward elsewhere.
kind_forward_free_pinned_port() {
  local pid cmd
  [[ "${OPENSHELL_LOCAL_PORT}" != 0 ]] || return 0
  require_cmd lsof
  for pid in $(lsof -nP -tiTCP:"${OPENSHELL_LOCAL_PORT}" -sTCP:LISTEN 2>/dev/null | sort -u || true); do
    if is_port_forward "${pid}"; then
      log "ending stale kubectl port-forward holding port ${OPENSHELL_LOCAL_PORT} (pid ${pid})"
      kill "${pid}" 2>/dev/null || true
      wait_until 10 process_gone "${pid}" || fail "port-forward ${pid} on ${OPENSHELL_LOCAL_PORT} did not end"
    else
      cmd="$(ps -o command= -p "${pid}" 2>/dev/null || true)"
      fail "port ${OPENSHELL_LOCAL_PORT} is held by process ${pid} (${cmd:0:80}); stop it or set OPENSHELL_LOCAL_PORT"
    fi
  done
}

# kind_forward_start: port-forwards to the gateway Service (gRPC) and to the
# StatefulSet pod's health port, which the Service does not expose. kubectl
# picks the local ports (OPENSHELL_LOCAL_PORT pins the gateway one) and the
# wrapper reads them back from its output. kubectl is started directly, not
# through the kctl function, so $! is its own pid and the stop ends it
# rather than an intermediate shell. The pids are recorded so the next run
# can end what an interrupted one left behind.
kind_forward_start() {
  local glog="${APF_E2E_LOG_DIR}/port-forward-gateway.log" hlog="${APF_E2E_LOG_DIR}/port-forward-health.log"
  mkdir -p "${APF_E2E_LOG_DIR}"
  kind_forward_release
  kind_forward_free_pinned_port
  : >"${glog}"
  : >"${hlog}"
  kubectl --context "${KIND_CONTEXT}" -n "${OPENSHELL_NS}" port-forward "svc/${OPENSHELL_SERVICE}" \
    "${OPENSHELL_LOCAL_PORT}:${OPENSHELL_SERVICE_PORT}" >"${glog}" 2>&1 &
  PF_GATEWAY_PID=$!
  kubectl --context "${KIND_CONTEXT}" -n "${OPENSHELL_NS}" port-forward "statefulset/${OPENSHELL_RELEASE}" \
    0:health >"${hlog}" 2>&1 &
  PF_HEALTH_PID=$!
  printf '%s\n%s\n' "${PF_GATEWAY_PID}" "${PF_HEALTH_PID}" >"${PF_PIDS_FILE}"
  forward_wait "${glog}" || { cat "${glog}" >&2; fail "gateway port-forward did not start"; }
  forward_wait "${hlog}" || { cat "${hlog}" >&2; fail "health port-forward did not start"; }
  GATEWAY_LOCAL_PORT="$(forward_port "${glog}")"
  HEALTH_LOCAL_PORT="$(forward_port "${hlog}")"
  ok "port-forwards: 127.0.0.1:${GATEWAY_LOCAL_PORT} -> svc/${OPENSHELL_SERVICE}:${OPENSHELL_SERVICE_PORT}, 127.0.0.1:${HEALTH_LOCAL_PORT} -> statefulset/${OPENSHELL_RELEASE}:health"
}

kind_forward_stop() {
  local pid
  for pid in "${PF_GATEWAY_PID}" "${PF_HEALTH_PID}"; do
    [[ -n "${pid}" ]] || continue
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    wait_until 10 process_gone "${pid}" || log "port-forward ${pid} is still running"
  done
  [[ -z "${PF_GATEWAY_PID}${PF_HEALTH_PID}" ]] || rm -f "${PF_PIDS_FILE}"
  PF_GATEWAY_PID=""
  PF_HEALTH_PID=""
}

uninstall_release() {
  local release="$1" ns="$2"
  if helmk status "${release}" --namespace "${ns}" >/dev/null 2>&1; then
    helmk uninstall "${release}" --namespace "${ns}" --wait --timeout 5m
    ok "release ${ns}/${release} uninstalled"
  else
    log "release ${ns}/${release} not installed"
  fi
}

# kind_down [cluster]: uninstalls both releases and deletes their namespaces;
# `cluster` also deletes the kind cluster. Sandboxes live in the OpenShell
# namespace; deleting the Sandbox objects first keeps their finalizers from
# stalling the namespace deletion.
kind_down() {
  local ns
  require_cmd helm kubectl kind
  if ! cluster_exists; then
    log "kind cluster ${KIND_CLUSTER} does not exist; nothing to tear down"
    return 0
  fi
  helm_recover "${APF_RELEASE}" "${APF_NS}"
  uninstall_release "${APF_RELEASE}" "${APF_NS}"
  kctl -n "${OPENSHELL_NS}" delete sandboxes.agents.x-k8s.io --all --wait=false >/dev/null 2>&1 || true
  helm_recover "${OPENSHELL_RELEASE}" "${OPENSHELL_NS}"
  uninstall_release "${OPENSHELL_RELEASE}" "${OPENSHELL_NS}"
  for ns in "${APF_NS}" "${OPENSHELL_NS}"; do
    if kctl get namespace "${ns}" >/dev/null 2>&1; then
      kctl delete namespace "${ns}" --wait=true --timeout=5m
      ok "namespace ${ns} deleted"
    fi
  done
  [[ "${1:-}" == cluster ]] && kind_cluster_down
  return 0
}

# kind_detect_running: for --existing. Fails unless both releases are
# installed and the APF Deployment is available; sets the PIP lane from the
# pod's containers and makes sure the grpcurl image is in the node.
kind_detect_running() {
  cluster_exists || fail "kind cluster ${KIND_CLUSTER} does not exist; bring the stack up first"
  kctl cluster-info >/dev/null 2>&1 || fail "context ${KIND_CONTEXT} is not reachable"
  helmk status "${APF_RELEASE}" -n "${APF_NS}" >/dev/null 2>&1 || fail "release ${APF_NS}/${APF_RELEASE} is not installed; bring the stack up first"
  helmk status "${OPENSHELL_RELEASE}" -n "${OPENSHELL_NS}" >/dev/null 2>&1 || fail "release ${OPENSHELL_NS}/${OPENSHELL_RELEASE} is not installed; bring the stack up first"
  local available containers
  available="$(kctl -n "${APF_NS}" get deployment "${APF_FULLNAME}" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || true)"
  [[ "${available:-0}" -ge 1 ]] || fail "deployment ${APF_NS}/${APF_FULLNAME} has no available replica"
  containers="$(kctl -n "${APF_NS}" get pod -l "app.kubernetes.io/instance=${APF_RELEASE}" -o jsonpath='{.items[0].spec.containers[*].name}' 2>/dev/null || true)"
  APF_E2E_PIP=0
  case " ${containers} " in
    *" pip-stub "*) APF_E2E_PIP=1 ;;
  esac
  if ! helmk get values "${OPENSHELL_RELEASE}" -n "${OPENSHELL_NS}" -o json 2>/dev/null | grep -q 'openshell.gateway.interceptors'; then
    log "the OpenShell release carries no gatewayConfig registration of APF; the OpenShell checks will fail"
  fi
  GRPCURL_NODE_IMAGE="$(kind_preload_image "${GRPCURL_IMAGE}")"
  log "cluster ${KIND_CLUSTER}: both releases installed, APF available, PIP ${APF_E2E_PIP}"
}

# kind_export_contract: the APF_E2E_* variables suites read.
kind_export_contract() {
  APF_E2E_OPENSHELL_CLI="$(openshell_cli_resolve)"
  APF_E2E_OPENSHELL_VERSION="${OPENSHELL_VERSION}"
  APF_E2E_BUNDLE_DIGEST="${APF_E2E_WORK}/bundle-v1.digest"
  APF_E2E_APF_DIR="${APF_DIR}"
  APF_E2E_GATEWAY_URL="http://127.0.0.1:${GATEWAY_LOCAL_PORT}"
  APF_E2E_HEALTH_URL="http://127.0.0.1:${HEALTH_LOCAL_PORT}"
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    APF_E2E_PIP_STUB_URL="http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}"
  else
    APF_E2E_PIP_STUB_URL=""
  fi
  export APF_E2E_ENV APF_E2E_OPENSHELL APF_E2E_PIP APF_E2E_WORK APF_E2E_LOG_DIR APF_E2E_GATEWAY_URL \
    APF_E2E_HEALTH_URL APF_E2E_OPENSHELL_CLI APF_E2E_OPENSHELL_VERSION APF_E2E_BUNDLE_DIGEST \
    APF_E2E_PIP_STUB_URL APF_E2E_SANDBOX_NAME APF_E2E_KEEP_SANDBOX APF_E2E_APF_DIR GRPCURL_NODE_IMAGE
}

kind_print_contract() {
  local v
  for v in APF_E2E_ENV APF_E2E_OPENSHELL APF_E2E_PIP APF_E2E_WORK APF_E2E_LOG_DIR APF_E2E_GATEWAY_URL \
    APF_E2E_HEALTH_URL APF_E2E_OPENSHELL_CLI APF_E2E_OPENSHELL_VERSION APF_E2E_BUNDLE_DIGEST \
    APF_E2E_PIP_STUB_URL APF_E2E_SANDBOX_NAME APF_E2E_KEEP_SANDBOX APF_E2E_APF_DIR; do
    printf '  %s=%s\n' "${v}" "${!v}"
  done
}
