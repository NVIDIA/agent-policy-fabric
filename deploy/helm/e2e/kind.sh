#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# kind.sh up|down|status
#
#   up      create the kind cluster, install agent-sandbox, load APF, OpenShell,
#           sandbox, and pip-stub images; safe to rerun
#   down    delete the kind cluster
#   status  show the cluster and its nodes

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER}"; }

image_present() { docker image inspect "$1" >/dev/null 2>&1; }

# load_image <image> [pull]: pulls the image for the host platform when it is
# missing and `pull` is given, then loads it into every kind node.
load_image() {
  local image="$1" pull="${2:-}"
  if ! image_present "${image}"; then
    [[ "${pull}" == pull ]] || fail "image ${image} is not present locally; build it first"
    log "pulling ${image}"
    docker pull "${image}"
  fi
  log "loading ${image} into kind cluster ${KIND_CLUSTER}"
  kind load docker-image "${image}" --name "${KIND_CLUSTER}"
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

up() {
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

  load_image "apf-policy-service:${APF_IMAGE_TAG}"
  load_image "apf-policy-gateway:${APF_IMAGE_TAG}"
  local component
  for component in gateway sandbox supervisor; do
    load_image "${OPENSHELL_IMAGE_REGISTRY}/${component}:${OPENSHELL_IMAGE_TAG}" pull
  done
  load_image "${SANDBOX_IMAGE}" pull
  if [[ "${PIP_ENABLED}" == 1 ]]; then
    load_image "${PIP_STUB_IMAGE}" pull
  fi
  ok "images loaded"
}

down() {
  require_cmd kind
  if cluster_exists; then
    kind delete cluster --name "${KIND_CLUSTER}"
    ok "deleted kind cluster ${KIND_CLUSTER}"
  else
    log "kind cluster ${KIND_CLUSTER} does not exist"
  fi
}

status() {
  require_cmd kind kubectl
  if cluster_exists; then
    ok "kind cluster ${KIND_CLUSTER} exists"
    kctl get nodes -o wide
    kctl get pods -A
  else
    log "kind cluster ${KIND_CLUSTER} does not exist"
    return 1
  fi
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: kind.sh up|down|status" >&2; exit 2 ;;
esac
