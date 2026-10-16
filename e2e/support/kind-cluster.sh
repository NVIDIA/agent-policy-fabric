# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Kind cluster lifecycle, sourced by e2e/with-kind-stack.sh after
# env-kind.sh: cluster create and delete, the agent-sandbox install and the
# image preload. Every function is safe to rerun.

# Node-side references of the preloaded fixture images, written by the
# cluster step for the wrapper, which runs the step in a pipeline.
NODE_IMAGES_ENV="${APF_E2E_WORK}/node-images.env"

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER}"; }

# kind_preload_image <reference> [reload]: makes the image available in the
# kind node and prints the node-side reference. A tag reference is pulled
# when missing and loaded as is. A digest reference cannot be loaded as such
# (the node ends up with no image resolvable by it), so it is pulled when
# missing, tagged <repository>:apf-e2e-<first 12 hex of the digest> and that
# tag is loaded. Images already in the node are skipped unless `reload` is
# given, which also refuses to pull: the APF images are local builds.
kind_preload_image() {
  local ref="$1" mode="${2:-}" node_ref="$1" digest short
  digest="$(image_digest "${ref}")"
  if [[ -n "${digest}" ]]; then
    short="${digest#sha256:}"
    node_ref="$(image_repository "${ref}"):apf-e2e-${short:0:12}"
  fi
  if [[ "${mode}" != reload ]] && kind_node_has_image "${node_ref}"; then
    log "image ${node_ref} present in node ${KIND_NODE}" >&2
    printf '%s\n' "${node_ref}"
    return 0
  fi
  if ! docker image inspect "${ref}" >/dev/null 2>&1; then
    [[ "${mode}" != reload ]] || fail "image ${ref} is not present locally; build it first"
    log "pulling ${ref}" >&2
    docker pull "${ref}" >&2
  fi
  [[ -z "${digest}" ]] || docker tag "${ref}" "${node_ref}"
  log "loading ${node_ref} into kind cluster ${KIND_CLUSTER}" >&2
  kind load docker-image "${node_ref}" --name "${KIND_CLUSTER}" >&2
  printf '%s\n' "${node_ref}"
}

install_agent_sandbox() {
  local base="https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}"
  if kctl get crd sandboxes.agents.x-k8s.io >/dev/null 2>&1; then
    log "agent-sandbox CRDs already installed"
  else
    log "installing agent-sandbox ${AGENT_SANDBOX_VERSION}"
    kctl apply -f "${base}/sandbox.yaml"
  fi
  local deadline=$(( $(date +%s) + 120 )) established=""
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    established="$(kctl get crd sandboxes.agents.x-k8s.io \
      -o 'jsonpath={.status.conditions[?(@.type=="Established")].status}' 2>/dev/null || true)"
    [[ "${established}" == "True" ]] && break
    sleep 2
  done
  [[ "${established}" == "True" ]] || fail "agent-sandbox Sandbox CRD did not become Established"
  wait_for_rollout agent-sandbox-system deployment/agent-sandbox-controller 300s
  ok "agent-sandbox ${AGENT_SANDBOX_VERSION} ready"
}

# kind_cluster_up: the cluster, agent-sandbox and every image the run needs
# in the node. The APF images are reloaded on every run; fixture images are
# skipped when the node already has them.
kind_cluster_up() {
  require_cmd kind kubectl docker
  docker info >/dev/null 2>&1 || fail "docker daemon not reachable"
  if cluster_exists; then
    log "kind cluster ${KIND_CLUSTER} already exists"
  else
    log "creating kind cluster ${KIND_CLUSTER}"
    kind create cluster --name "${KIND_CLUSTER}" --wait 120s
  fi
  kctl cluster-info >/dev/null
  ok "cluster ${KIND_CLUSTER} reachable via context ${KIND_CONTEXT}"

  install_agent_sandbox

  kind_preload_image "apf-policy-service:${APF_IMAGE_TAG}" reload >/dev/null
  kind_preload_image "apf-policy-gateway:${APF_IMAGE_TAG}" reload >/dev/null
  local component sandbox grpcurl pip_stub=""
  for component in gateway sandbox supervisor; do
    kind_preload_image "${OPENSHELL_IMAGE_REGISTRY}/${component}:${OPENSHELL_IMAGE_TAG}" >/dev/null
  done
  sandbox="$(kind_preload_image "${SANDBOX_IMAGE}")"
  grpcurl="$(kind_preload_image "${GRPCURL_IMAGE}")"
  if [[ "${APF_E2E_PIP}" == 1 ]]; then
    pip_stub="$(kind_preload_image "${PIP_STUB_IMAGE}")"
  fi
  mkdir -p "$(dirname "${NODE_IMAGES_ENV}")"
  {
    printf "SANDBOX_NODE_IMAGE='%s'\n" "${sandbox}"
    printf "GRPCURL_NODE_IMAGE='%s'\n" "${grpcurl}"
    printf "PIP_STUB_NODE_IMAGE='%s'\n" "${pip_stub}"
  } >"${NODE_IMAGES_ENV}"
  ok "images loaded (sandbox ${sandbox}, grpcurl ${grpcurl})"
}

kind_cluster_down() {
  require_cmd kind
  if cluster_exists; then
    kind delete cluster --name "${KIND_CLUSTER}"
    ok "deleted kind cluster ${KIND_CLUSTER}"
  else
    log "kind cluster ${KIND_CLUSTER} does not exist"
  fi
}
