#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# up.sh [--skip-cluster]
#
# Brings APF up on a kind cluster next to an OpenShell gateway and runs smoke.sh:
#   1. kind cluster, agent-sandbox, images            (kind.sh up)
#   2. OpenShell without extensions                   (creates the JWT Secret)
#   3. materials: bundles, cert, trust, Secrets/CMs   (materials.sh)
#   4. APF chart, with the pip-stub sidecar when PIP is enabled
#   5. OpenShell again with the APF registration overlay
#   6. smoke checks                                   (smoke.sh)
# --skip-cluster reuses the existing cluster and images.
# --render-only writes the environment-adjusted values files into E2E_WORK and stops.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

SKIP_CLUSTER=0
RENDER_ONLY=0
for arg in "$@"; do
  case "${arg}" in
    --skip-cluster) SKIP_CLUSTER=1 ;;
    --render-only) RENDER_ONLY=1 ;;
    -h|--help) sed -n '5,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

require_cmd helm kubectl yq
LOG_DIR="${E2E_WORK}/logs"
mkdir -p "${E2E_WORK}" "${LOG_DIR}"

# step <slug> <title> <command...>: runs the command, tees its output to
# E2E_WORK/logs/<slug>.log, and dumps cluster state when it fails.
step() {
  local slug="$1" title="$2"
  shift 2
  banner "${title}"
  log "log: ${LOG_DIR}/${slug}.log"
  if ! "$@" 2>&1 | tee "${LOG_DIR}/${slug}.log"; then
    printf '\n%sstep failed: %s%s\n' "${C_RED}" "${title}" "${C_RESET}" >&2
    dump_cluster_state
    exit 1
  fi
}

# The checked-in values files assume the default names; rewrite them from the
# environment into E2E_WORK so env knobs (namespaces, tags, ports) take effect.
render_values() {
  local sandbox_repo="${SANDBOX_IMAGE%:*}" sandbox_tag="${SANDBOX_IMAGE##*:}"
  [[ "${SANDBOX_IMAGE}" == *:* ]] || sandbox_tag="latest"
  OS_TAG="${OPENSHELL_IMAGE_TAG}" SANDBOX_REPO="${sandbox_repo}" SANDBOX_TAG="${sandbox_tag}" \
    yq '.global.image.tag = strenv(OS_TAG)
        | .sandbox.image.repository = strenv(SANDBOX_REPO)
        | .sandbox.image.tag = strenv(SANDBOX_TAG)' \
    "${E2E_DIR}/openshell-values.yaml" >"${E2E_WORK}/openshell-values.yaml"

  # The stanza keys are OpenShell's: sandbox admission registers under
  # openshell.gateway.interceptors, egress request policy under
  # openshell.supervisor.middleware.
  ADMISSION_ENDPOINT="https://${APF_SERVICE_HOST}:${APF_ADMISSION_PORT}" \
  EGRESS_ENDPOINT="https://${APF_SERVICE_HOST}:${APF_EGRESS_PORT}" \
    yq '.gatewayConfig["openshell.gateway.interceptors"][0].grpc_endpoint = strenv(ADMISSION_ENDPOINT)
        | .gatewayConfig["openshell.gateway.interceptors"][0].audience = strenv(INTERCEPTOR_AUDIENCE)
        | .gatewayConfig["openshell.supervisor.middleware"][0].grpc_endpoint = strenv(EGRESS_ENDPOINT)
        | .gatewayConfig["openshell.supervisor.middleware"][0].audience = strenv(MIDDLEWARE_AUDIENCE)' \
    "${E2E_DIR}/openshell-values-apf.yaml" >"${E2E_WORK}/openshell-values-apf.yaml"

  yq '.fullnameOverride = strenv(APF_FULLNAME)
      | .policyService.image.tag = strenv(APF_IMAGE_TAG)
      | .policyGateway.image.tag = strenv(APF_IMAGE_TAG)
      | .policyGateway.openshell.gatewayEndpoint = strenv(OPENSHELL_GATEWAY_URL)
      | .policyGateway.openshell.admission.port = env(APF_ADMISSION_PORT)
      | .policyGateway.openshell.egress.port = env(APF_EGRESS_PORT)' \
    "${E2E_DIR}/apf-values.yaml" >"${E2E_WORK}/apf-values.yaml"

  PIP_STUB_HEALTH_URL="http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}" \
    yq '.extraContainers[0].image = strenv(PIP_STUB_IMAGE)
        | .extraContainers[0].command[3] = strenv(PIP_STUB_PORT)
        | (.extraContainers[0].env[] | select(.name == "PIP_STUB_HEALTH_URL")).value = strenv(PIP_STUB_HEALTH_URL)' \
    "${E2E_DIR}/apf-values-pip.yaml" >"${E2E_WORK}/apf-values-pip.yaml"
  ok "values rendered into ${E2E_WORK}"
}

install_openshell_plain() {
  helmk upgrade --install "${OPENSHELL_RELEASE}" "${OPENSHELL_CHART}" --version "${OPENSHELL_VERSION}" \
    --namespace "${OPENSHELL_NS}" --create-namespace \
    --values "${E2E_WORK}/openshell-values.yaml" \
    --wait --timeout 10m
  wait_for_rollout "${OPENSHELL_NS}" "statefulset/${OPENSHELL_RELEASE}" 300s
}

install_apf() {
  local extra=()
  [[ "${PIP_ENABLED}" == 1 ]] && extra=(--values "${E2E_WORK}/apf-values-pip.yaml")
  helm lint --strict "${CHART_DIR}" --values "${E2E_WORK}/apf-values.yaml" "${extra[@]+"${extra[@]}"}"
  helmk upgrade --install "${APF_RELEASE}" "${CHART_DIR}" \
    --namespace "${APF_NS}" --create-namespace \
    --values "${E2E_WORK}/apf-values.yaml" "${extra[@]+"${extra[@]}"}" \
    --wait --timeout 5m
  wait_for_rollout "${APF_NS}" "deployment/${APF_FULLNAME}" 300s
}

register_apf_with_openshell() {
  helmk upgrade "${OPENSHELL_RELEASE}" "${OPENSHELL_CHART}" --version "${OPENSHELL_VERSION}" \
    --namespace "${OPENSHELL_NS}" \
    --values "${E2E_WORK}/openshell-values.yaml" \
    --values "${E2E_WORK}/openshell-values-apf.yaml" \
    --wait --timeout 10m
  wait_for_rollout "${OPENSHELL_NS}" "statefulset/${OPENSHELL_RELEASE}" 300s
}

banner "APF chart verification on kind (${KIND_CLUSTER})"
log "bundle: ${BUNDLE_SRC}"
log "PIP enabled: ${PIP_ENABLED}"
log "work dir: ${E2E_WORK}"
log "OpenShell under test: ${OPENSHELL_VERSION}; APF proto pin: ${APF_OPENSHELL_PIN:-unknown}"
if [[ -n "${APF_OPENSHELL_PIN}" && "${APF_OPENSHELL_PIN}" != "${OPENSHELL_VERSION}" ]]; then
  log "the versions differ: the extension protocol major version decides compatibility, and step 5 fails if the gateway cannot negotiate with APF"
fi

if [[ "${RENDER_ONLY}" == 1 ]]; then
  render_values
  exit 0
fi
if [[ "${SKIP_CLUSTER}" == 1 ]]; then
  log "reusing existing cluster ${KIND_CLUSTER} (--skip-cluster)"
  kctl cluster-info >/dev/null || fail "context ${KIND_CONTEXT} is not reachable"
else
  step 1-kind "1/6 kind cluster, agent-sandbox, images" "${E2E_DIR}/kind.sh" up
fi
render_values
step 2-openshell "2/6 OpenShell ${OPENSHELL_VERSION} without extensions" install_openshell_plain
step 3-materials "3/6 bundles, certificate, trust profiles, Secrets and ConfigMaps" "${E2E_DIR}/materials.sh"
if [[ "${PIP_ENABLED}" == 1 ]]; then
  step 4-apf "4/6 APF chart with the pip-stub sidecar" install_apf
else
  step 4-apf "4/6 APF chart" install_apf
fi
step 5-register "5/6 OpenShell with the APF registration overlay" register_apf_with_openshell
step 6-smoke "6/6 smoke checks" "${E2E_DIR}/smoke.sh"

banner "done"
log "tear down with: ${E2E_DIR}/down.sh [--cluster]"
