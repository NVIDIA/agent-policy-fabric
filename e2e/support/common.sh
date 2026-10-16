# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers and fixture knobs of the verification harness, sourced by the
# environment wrappers, the environment files and the suites. Every knob can
# be overridden from the environment. Defaults stay inside this repository so
# the harness runs from a clone of apf alone; a demo composes it by pointing
# the knobs at its own material.

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APF_DIR="$(cd "${E2E_DIR}/.." && pwd)"

# Work root (gitignored). Each environment keeps its outputs under
# E2E_WORK/<environment>; the OpenShell CLI lives at E2E_WORK/openshell.
E2E_WORK="${E2E_WORK:-${E2E_DIR}/.work}"

# Images under test and the fixture images. `latest` is refused by preflight.
APF_IMAGE_TAG="${APF_IMAGE_TAG:-dev}"
OPENSHELL_IMAGE_TAG="${OPENSHELL_IMAGE_TAG:-0.1.3}"
OPENSHELL_VERSION="${OPENSHELL_VERSION:-${OPENSHELL_IMAGE_TAG}}"
OPENSHELL_IMAGE_REGISTRY="${OPENSHELL_IMAGE_REGISTRY:-ghcr.io/nvidia/openshell}"
# Default image for `openshell sandbox create`. The Docker driver resolves the
# policy's run_as_user against the image, and the demo policy names `sandbox`,
# so the image must define that user; the community base image does.
SANDBOX_IMAGE="${SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:e29a8e98c1399aa08a8c624d758d1814b6edbe0302eb570c0468a6d3e811d167}"
# grpcurl v1.9.3, sends the EvaluateRequest fixtures over the gateway socket.
GRPCURL_IMAGE="${GRPCURL_IMAGE:-fullstorydev/grpcurl@sha256:085e183ca334eb4e81ca81ee12cbb2b2737505d1d77f5e33dabc5d066593d998}"
# The OpenShell CLI; resolved by openshell_cli_ensure when empty.
OPENSHELL_CLI="${OPENSHELL_CLI:-}"

# Listener ports of the policy gateway: sandbox admission (OpenShell gateway
# interceptor) and egress request policy (OpenShell supervisor middleware).
APF_ADMISSION_PORT="${APF_ADMISSION_PORT:-18081}"
APF_EGRESS_PORT="${APF_EGRESS_PORT:-9099}"

# Bundle signing: the development key, its id (also the trust-root file stem
# and the document key id both binaries use) and the signing tool.
APF_KEY_ID="${APF_KEY_ID:-apf-dev}"
SIGNING_KEY_ID="${SIGNING_KEY_ID:-${APF_KEY_ID}}"
DEV_KEYS_DIR="${DEV_KEYS_DIR:-${APF_DIR}/examples/dev-keys}"
APF_COMPILE="${APF_COMPILE:-${APF_DIR}/target/release/apf-compile}"

# The policy bundle source: a directory holding one *.template.yaml and the
# member files it lists. Revision 2 bumps policy_revision; BUNDLE_V2_TRANSFORM
# may name an executable that receives the staged directory and edits members
# before signing.
BUNDLE_SRC="${BUNDLE_SRC:-${APF_DIR}/examples/demo-bundle}"
BUNDLE_V2_TRANSFORM="${BUNDLE_V2_TRANSFORM:-}"

# Policy information provider lane: on when PIP_CONFIG_SRC names a
# registration (the wrappers' --pip selects the in-repo fixture). The stub
# script is served from the pod's loopback by a sidecar running the pinned
# python 3.12-slim image; it must accept --port and answer
# PIP_STUB_HEALTH_PATH with 200.
PIP_CONFIG_SRC="${PIP_CONFIG_SRC:-}"
PIP_STUB_SRC="${PIP_STUB_SRC:-${E2E_DIR}/configs/pip/stub.py}"
PIP_STUB_IMAGE="${PIP_STUB_IMAGE:-python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1}"
PIP_STUB_PORT="${PIP_STUB_PORT:-19500}"
PIP_STUB_HEALTH_PATH="${PIP_STUB_HEALTH_PATH:-/healthz}"

# Suite knobs: the sandbox the smoke suite creates, kept after the run when
# APF_E2E_KEEP_SANDBOX=1 (KEEP_SANDBOX is accepted as an alias).
APF_E2E_SANDBOX_NAME="${APF_E2E_SANDBOX_NAME:-apf-e2e}"
APF_E2E_KEEP_SANDBOX="${APF_E2E_KEEP_SANDBOX:-${KEEP_SANDBOX:-0}}"

export E2E_DIR APF_DIR E2E_WORK APF_IMAGE_TAG OPENSHELL_IMAGE_TAG OPENSHELL_VERSION \
  OPENSHELL_IMAGE_REGISTRY SANDBOX_IMAGE GRPCURL_IMAGE OPENSHELL_CLI \
  APF_ADMISSION_PORT APF_EGRESS_PORT APF_KEY_ID SIGNING_KEY_ID DEV_KEYS_DIR APF_COMPILE \
  BUNDLE_SRC BUNDLE_V2_TRANSFORM PIP_CONFIG_SRC PIP_STUB_SRC PIP_STUB_IMAGE PIP_STUB_PORT \
  PIP_STUB_HEALTH_PATH APF_E2E_SANDBOX_NAME APF_E2E_KEEP_SANDBOX

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m' C_BOLD=$'\033[1m' C_GREEN=$'\033[1;32m' C_RED=$'\033[1;31m' C_YELLOW=$'\033[1;33m' C_DIM=$'\033[2m'
else
  C_RESET="" C_BOLD="" C_GREEN="" C_RED="" C_YELLOW="" C_DIM=""
fi

log()    { printf '%s  %s%s\n' "${C_DIM}" "$*" "${C_RESET}"; }
banner() { printf '\n%s== %s ==%s\n' "${C_BOLD}" "$*" "${C_RESET}"; }
ok()     { printf '%s  ok   %s%s\n' "${C_GREEN}" "$*" "${C_RESET}"; }
skip()   { printf '%s  skip %s%s\n' "${C_YELLOW}" "$*" "${C_RESET}"; }
fail()   { printf '%s  FAIL %s%s\n' "${C_RED}" "$*" "${C_RESET}" >&2; exit 1; }

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || fail "required command not found on PATH: $c"
  done
}

# wait_until <seconds> <command...>: polls the command every 3 seconds until
# it succeeds or the deadline passes; the last attempt's status is returned.
wait_until() {
  local deadline=$(( $(date +%s) + $1 ))
  shift
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    "$@" && return 0
    sleep 3
  done
  "$@"
}

# Removes the ANSI colour codes the OpenShell gateway writes into its log.
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g'; }

# step <slug> <title> <command...>: runs the command, tees its output to
# APF_E2E_LOG_DIR/<slug>.log and, when it fails, appends the environment's
# state dump (apf_e2e_dump_state) to the log and stderr. Returns the
# command's status; the caller decides whether to tear down.
step() {
  local slug="$1" title="$2"
  shift 2
  mkdir -p "${APF_E2E_LOG_DIR}"
  banner "${title}"
  log "log: ${APF_E2E_LOG_DIR}/${slug}.log"
  if "$@" 2>&1 | tee "${APF_E2E_LOG_DIR}/${slug}.log"; then
    return 0
  fi
  printf '\n%sstep failed: %s%s\n' "${C_RED}" "${title}" "${C_RESET}" >&2
  if declare -F apf_e2e_dump_state >/dev/null; then
    apf_e2e_dump_state 2>&1 | tee -a "${APF_E2E_LOG_DIR}/${slug}.log" >&2 || true
  fi
  return 1
}

# Image reference helpers: `registry/repo:tag`, `registry/repo@sha256:…` or
# `registry/repo`. image_tag prints nothing for a digest reference.
image_digest() {
  case "$1" in
    *@*) printf '%s' "${1#*@}" ;;
    *) printf '' ;;
  esac
}
image_repository() {
  local ref="${1%%@*}" last="${1%%@*}"
  last="${last##*/}"
  case "${last}" in
    *:*) printf '%s' "${ref%:*}" ;;
    *) printf '%s' "${ref}" ;;
  esac
}
image_tag() {
  local last
  case "$1" in
    *@*) printf ''; return 0 ;;
  esac
  last="${1##*/}"
  case "${last}" in
    *:*) printf '%s' "${last##*:}" ;;
    *) printf '' ;;
  esac
}

# write_run_env <path> <variable>...: records the knobs a run was rendered
# with as `: "${NAME:=value}"` lines. Sourced before the defaults apply, the
# file supplies the run's values to --existing, --logs and --down while a
# value set in the caller's environment still wins.
write_run_env() {
  local path="$1" name value
  shift
  mkdir -p "$(dirname "${path}")"
  {
    echo "# Knobs this run was rendered with. Sourced as defaults by the wrapper's"
    echo "# --existing, --logs and --down; the caller's environment takes precedence."
    for name in "$@"; do
      value="${!name:-}"
      value="${value//\\/\\\\}"
      value="${value//\"/\\\"}"
      value="${value//\$/\\\$}"
      value="${value//\`/\\\`}"
      printf ': "${%s:=%s}"\n' "${name}" "${value}"
    done
  } >"${path}"
}
