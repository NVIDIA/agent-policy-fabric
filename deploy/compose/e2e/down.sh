#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# down.sh [--volumes]
#
# Stops and removes the stack, including the OpenShell overlay and any sandbox
# containers its gateway created. --volumes also removes the named volumes
# (anti-rollback counter, secrets, OpenShell material) and the OpenShell state
# directory. E2E_WORK is kept.

set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

REMOVE_VOLUMES=0
for arg in "$@"; do
  case "${arg}" in
    --volumes) REMOVE_VOLUMES=1 ;;
    *) echo "usage: down.sh [--volumes]" >&2; exit 2 ;;
  esac
done

require_cmd docker

# Sandboxes are containers the OpenShell gateway created outside compose,
# labelled openshell.ai/sandbox-namespace with the sandbox_label the gateway
# TOML sets, which is the gateway id.
sandboxes="$(docker ps -a -q --filter "label=openshell.ai/sandbox-namespace=${OPENSHELL_GATEWAY_ID}" 2>/dev/null || true)"
if [[ -n "${sandboxes}" ]]; then
  # shellcheck disable=SC2086
  docker rm -f ${sandboxes} >/dev/null
  ok "removed $(wc -w <<<"${sandboxes}" | tr -d ' ') sandbox container(s) of namespace ${OPENSHELL_GATEWAY_ID}"
fi

args=(down --remove-orphans)
[[ "${REMOVE_VOLUMES}" == 1 ]] && args+=(--volumes)
COMPOSE_FILES_SCOPE=all compose "${args[@]}"
ok "project ${COMPOSE_PROJECT_NAME} down"

if [[ "${REMOVE_VOLUMES}" == 1 && -d "${OPENSHELL_STATE_DIR}" ]]; then
  if rm -rf "${OPENSHELL_STATE_DIR}" 2>/dev/null; then
    ok "removed ${OPENSHELL_STATE_DIR}"
  else
    log "could not remove ${OPENSHELL_STATE_DIR} (root-owned files); remove it with elevated privileges"
  fi
fi
