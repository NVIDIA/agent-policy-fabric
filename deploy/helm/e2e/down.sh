#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# down.sh [--cluster]
#
# Uninstalls the APF and OpenShell releases and deletes their namespaces.
# --cluster also deletes the kind cluster. E2E_WORK is kept.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

DELETE_CLUSTER=0
for arg in "$@"; do
  case "${arg}" in
    --cluster) DELETE_CLUSTER=1 ;;
    *) echo "usage: down.sh [--cluster]" >&2; exit 2 ;;
  esac
done

require_cmd helm kubectl kind

if ! kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER}"; then
  log "kind cluster ${KIND_CLUSTER} does not exist; nothing to tear down"
  exit 0
fi

uninstall_release() {
  local release="$1" ns="$2"
  if helmk status "${release}" --namespace "${ns}" >/dev/null 2>&1; then
    helmk uninstall "${release}" --namespace "${ns}" --wait --timeout 5m
    ok "release ${ns}/${release} uninstalled"
  else
    log "release ${ns}/${release} not installed"
  fi
}

uninstall_release "${APF_RELEASE}" "${APF_NS}"
uninstall_release "${OPENSHELL_RELEASE}" "${OPENSHELL_NS}"

for ns in "${APF_NS}" "${OPENSHELL_NS}"; do
  if kctl get namespace "${ns}" >/dev/null 2>&1; then
    kctl delete namespace "${ns}" --wait=true --timeout=5m
    ok "namespace ${ns} deleted"
  fi
done

if [[ "${DELETE_CLUSTER}" == 1 ]]; then
  "${E2E_DIR}/kind.sh" down
fi
