#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# parity.sh: static check that the compose stack and the Helm chart start the
# two APF binaries with the same flags, modulo the paths and addresses each
# environment chooses. The compose side is deploy/docker/compose.yaml with
# the verification overlays, rendered by `docker compose config`; the chart
# side is deploy/helm/apf with the kind values, rendered by `helm template`.
# No stack and no engine are needed. Prints one table per lane and binary and
# exits 1 on any difference that is not listed below with a reason.
#
# Lanes:
#   standalone     compose.yaml alone against the chart in its listener-less
#                  shape (insecure admission transport, egress off, no gateway
#                  endpoint); the chart always serves the sandbox admission
#                  listener, so its two flags for it are chart-only by design
#   openshell      the OpenShell overlay against e2e/configs/kind/apf-values.yaml
#   openshell+pip  the OpenShell and provider overlays against apf-values.yaml
#                  plus apf-values-pip.yaml

set -euo pipefail
# shellcheck source=../support/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/support/common.sh"
require_cmd docker helm yq sort join awk

COMPOSE_DIR="${APF_DIR}/deploy/docker"
CHART_DIR="${APF_DIR}/deploy/helm/apf"
KIND_VALUES="${E2E_DIR}/configs/kind"
COMPOSE_OVERLAYS="${E2E_DIR}/configs/compose"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/apf-parity.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# Flags compared by name only: their value is a path or an address each
# environment chooses (socket directories, mounted files, service URLs).
BY_NAME="--socket --policy-service-socket --bundle-path --document-signing-key --trust-root-dir
  --http-bearer-token-file --audit-log-dir --pip-config --openshell-gateway-url --jwks-url --http-addr
  --openshell-interceptor-addr --openshell-middleware-addr
  --openshell-interceptor-tls-cert-file --openshell-interceptor-tls-key-file --openshell-interceptor-auth-trust-file
  --openshell-middleware-tls-cert-file --openshell-middleware-tls-key-file --openshell-middleware-auth-trust-file"

# Flags one side may carry alone: flag|side|lanes|reason. `*` means every lane.
ALLOWED="--document-ttl-secs|chart|*|the kind values set policyService.documentTtlSecs; compose uses the binary default
--pip-stage-budget-ms|chart|*|values-driven; set only when policyGateway.pip.stageBudgetMs is above 0
--openshell-interceptor-addr|chart|standalone|the chart always serves the sandbox admission listener
--openshell-interceptor-allow-insecure-transport|chart|standalone|the chart always serves the sandbox admission listener"

# Compose passes some settings as environment variables the binaries read as
# flags; every APF_* entry must be in this table or the lane fails.
ENV_TO_FLAG="APF_PIP_CONFIG=--pip-config"

# flags_normalize: `--flag=value` -> `--flag<TAB>value`, `--flag` -> `--flag<TAB>(set)`, sorted.
flags_normalize() {
  awk '{
    line = $0
    sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
    if (line == "") next
    eq = index(line, "=")
    if (eq > 0) printf "%s\t%s\n", substr(line, 1, eq - 1), substr(line, eq + 1)
    else printf "%s\t(set)\n", line
  }' | LC_ALL=C sort -u
}

# compose_flags <lane> <service> <out>: the service's command plus its APF_*
# environment entries mapped to flags.
compose_flags() {
  local lane="$1" svc="$2" out="$3" rendered="${WORK}/compose-${lane}.yaml" entry name value flag
  if [[ ! -f "${rendered}" ]]; then
    local files=(-f "${COMPOSE_DIR}/compose.yaml")
    case "${lane}" in
      openshell|openshell+pip) files+=(-f "${COMPOSE_OVERLAYS}/compose.openshell.yaml") ;;
    esac
    [[ "${lane}" == openshell+pip ]] && files+=(-f "${COMPOSE_OVERLAYS}/compose.pip.yaml")
    APF_BUNDLE_DIR=/placeholder/bundle APF_TRUST_ROOT=/placeholder/apf-dev.pub \
    OPENSHELL_STATE_DIR=/placeholder/state OPENSHELL_GATEWAY_TOML=/placeholder/gateway.toml \
    CONTAINER_SOCKET=/placeholder/engine.sock PIP_CONFIG=/placeholder/pips.yaml PIP_STUB_SRC=/placeholder/stub.py \
      docker compose --project-directory "${COMPOSE_DIR}" "${files[@]}" config >"${rendered}"
  fi
  {
    yq ".services[\"${svc}\"].command[]" "${rendered}"
    while IFS= read -r entry; do
      [[ -n "${entry}" ]] || continue
      name="${entry%%=*}"
      value="${entry#*=}"
      flag="$(awk -v n="${name}" '{ split($0, kv, "="); if (kv[1] == n) print kv[2] }' <<<"${ENV_TO_FLAG}")"
      [[ -n "${flag}" ]] || fail "lane ${lane}: compose sets ${name} on ${svc}, which the environment-to-flag table does not know"
      printf '%s=%s\n' "${flag}" "${value}"
    done < <(yq ".services[\"${svc}\"].environment // {} | to_entries[] | select(.key | test(\"^APF_\")) | .key + \"=\" + .value" "${rendered}")
  } | flags_normalize >"${out}"
}

# chart_flags <lane> <container> <out>: the container's args from the chart.
chart_flags() {
  local lane="$1" container="$2" out="$3" rendered="${WORK}/chart-${lane}.yaml"
  if [[ ! -f "${rendered}" ]]; then
    local args=(-f "${KIND_VALUES}/apf-values.yaml")
    case "${lane}" in
      standalone)
        args+=(--set policyGateway.openshell.admission.allowInsecureTransport=true
          --set policyGateway.openshell.egress.enabled=false
          --set policyGateway.openshell.gatewayEndpoint=)
        ;;
      openshell+pip) args+=(-f "${KIND_VALUES}/apf-values-pip.yaml") ;;
    esac
    helm template apf "${CHART_DIR}" "${args[@]}" >"${rendered}"
  fi
  yq "select(.kind == \"Deployment\") | .spec.template.spec.containers[] | select(.name == \"${container}\") | .args[]" "${rendered}" \
    | flags_normalize >"${out}"
}

# compare <lane> <binary> <compose-file> <chart-file>: prints the table and
# returns 1 when an unlisted difference exists.
compare() {
  local lane="$1" binary="$2"
  printf '\n  %s / %s\n' "${lane}" "${binary}"
  printf '  %-50s %-30s %-30s %s\n' flag compose chart verdict
  LC_ALL=C join -t "$(printf '\t')" -a1 -a2 -e '<absent>' -o 0,1.2,2.2 "$3" "$4" \
    | awk -F'\t' -v lane="${lane}" -v byname="$(tr -s ' \t\n' ' ' <<<"${BY_NAME}")" -v allowed="$(tr '\n' ';' <<<"${ALLOWED}")" '
      function show(v) {
        if (v == "<absent>") return "-"
        if (length(v) > 30) return substr(v, 1, 27) "..."
        return v
      }
      BEGIN {
        n = split(byname, a, " ")
        for (i = 1; i <= n; i++) if (a[i] != "") BN[a[i]] = 1
        m = split(allowed, b, ";")
        for (i = 1; i <= m; i++) {
          k = split(b[i], f, "|")
          if (k == 4) { AL_SIDE[f[1]] = f[2]; AL_LANES[f[1]] = f[3]; AL_REASON[f[1]] = f[4] }
        }
        bad = 0
      }
      {
        flag = $1; c = $2; h = $3; verdict = ""
        if (c == "<absent>" || h == "<absent>") {
          if (flag in AL_SIDE) {
            lanes = AL_LANES[flag]
            side_ok = (AL_SIDE[flag] == "chart" && c == "<absent>") || (AL_SIDE[flag] == "compose" && h == "<absent>")
            lane_ok = (lanes == "*" || lanes == lane)
            if (side_ok && lane_ok) verdict = "allowed: " AL_REASON[flag]
          }
          if (verdict == "") { verdict = "DIFF: only in " (c == "<absent>" ? "chart" : "compose"); bad = 1 }
        } else if (flag in BN) {
          verdict = "ok (by name)"
        } else if (c == h) {
          verdict = "ok"
        } else {
          verdict = "DIFF"; bad = 1
        }
        printf "  %-50s %-30s %-30s %s\n", flag, show(c), show(h), verdict
      }
      END { exit bad }'
}

banner "flag parity: compose stack vs Helm chart"
log "compose: ${COMPOSE_DIR}/compose.yaml with the overlays under ${COMPOSE_OVERLAYS}"
log "chart:   ${CHART_DIR} with the values under ${KIND_VALUES}"

FAILED=0
for lane in standalone openshell openshell+pip; do
  for binary in policy-service policy-gateway; do
    compose_flags "${lane}" "${binary}" "${WORK}/compose-${lane}-${binary}.tsv"
    chart_flags "${lane}" "${binary}" "${WORK}/chart-${lane}-${binary}.tsv"
    compare "${lane}" "${binary}" "${WORK}/compose-${lane}-${binary}.tsv" "${WORK}/chart-${lane}-${binary}.tsv" || FAILED=1
  done
done

echo
if [[ "${FAILED}" == 1 ]]; then
  printf '%s  FAIL flag sets differ beyond the listed exceptions%s\n' "${C_RED}" "${C_RESET}" >&2
  exit 1
fi
ok "compose and chart start both binaries with the same flags, modulo paths and the listed exceptions"
