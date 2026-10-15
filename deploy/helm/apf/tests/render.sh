#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -eu

chart=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

app_version=$(yq -r '.appVersion' "$chart/Chart.yaml")

# render <case> [helm args...]: renders the chart into the work directory and
# checks the resources every case shares. The expected file count covers the
# Deployment, Service, ServiceAccount, and state PVC.
render() {
  case_name=$1
  shift
  helm template test "$chart" --output-dir "$work/$case_name" "$@" >/dev/null

  templates="$work/$case_name/apf/templates"
  deployment="$templates/deployment.yaml"
  service="$templates/service.yaml"
  serviceaccount="$templates/serviceaccount.yaml"
  statepvc="$templates/state-pvc.yaml"
  networkpolicy="$templates/networkpolicy.yaml"
  test "$(yq -r '.kind' "$deployment")" = Deployment
  test "$(yq -r '.kind' "$service")" = Service
  test "$(yq -r '.spec.template.spec.automountServiceAccountToken' "$deployment")" = false
}

gateway() { yq -r ".spec.template.spec.containers[] | select(.name == \"policy-gateway\") | $1" "$deployment"; }
policy_service() { yq -r ".spec.template.spec.containers[] | select(.name == \"policy-service\") | $1" "$deployment"; }
volume() { yq -r ".spec.template.spec.volumes[] | select(.name == \"$1\") | $2" "$deployment"; }

check_file_count() {
  test "$(find "$templates" -type f | wc -l | tr -d ' ')" = "$1"
}

check_egress() {
  if test "$1" = off; then
    test "$(yq -r '.spec.ports | length' "$service")" = 1
    test "$(yq -r '.spec.ports[0].name' "$service")" = admission
    test "$(yq -r '.spec.ports[0].targetPort' "$service")" = admission
    test "$(gateway '.ports[0].name')" = admission
    test "$(gateway '.readinessProbe.tcpSocket.port')" = admission
    test -z "$(volume middleware-tls-src '.name')"
  else
    test "$(yq -r '.spec.ports | length' "$service")" = 2
    test "$(yq -r '.spec.ports[] | select(.name == "egress") | .port' "$service")" = 9099
    test "$(yq -r '.spec.ports[] | select(.name == "egress") | .targetPort' "$service")" = egress
    test "$(gateway '.ports[] | select(.name == "egress") | .containerPort')" = 9099
    test "$(gateway '.readinessProbe.tcpSocket.port')" = egress
    test "$(volume middleware-tls-src '.secret.secretName')" = egress-tls
  fi
}

check_source() {
  source=$1
  test "$(policy_service ".args[] | select(. == \"--policy-source=$source\")")" = "--policy-source=$source"
  if test "$source" = local; then
    test "$(volume bundle '.name')" = bundle
    test -z "$(volume bundle-download-tmp '.name')"
  else
    test -z "$(volume bundle '.name')"
    test "$(volume bundle-download-tmp '.name')" = bundle-download-tmp
  fi
}

must_fail() {
  label=$1
  shift
  if helm template test "$chart" "$@" >"$work/$label.log" 2>&1; then
    echo "Expected Helm to reject $label" >&2
    exit 1
  fi
}

helm lint --strict "$chart" >/dev/null

render defaults
check_file_count 4
check_egress off
check_source local
test "$(volume audit '.emptyDir.sizeLimit')" = null
test "$(yq -r '.kind' "$serviceaccount")" = ServiceAccount
test "$(yq -r '.metadata.name' "$serviceaccount")" = test-apf
test "$(yq -r '.automountServiceAccountToken' "$serviceaccount")" = false
test "$(yq -r '.spec.template.spec.serviceAccountName' "$deployment")" = test-apf
test "$(yq -r '.metadata.annotations["helm.sh/resource-policy"]' "$statepvc")" = keep
test "$(yq -r '.spec.strategy.type' "$deployment")" = Recreate
test "$(yq -r '.spec.template.spec.imagePullSecrets' "$deployment")" = null
test "$(yq -r '.spec.template.spec.securityContext.runAsUser' "$deployment")" = 65532
test "$(yq -r '.spec.template.metadata.annotations["apf-rollout-revision"]' "$deployment")" = ""
test "$(gateway '.image')" = "apf-policy-gateway:$app_version"
test "$(gateway '.imagePullPolicy')" = IfNotPresent
test "$(policy_service '.image')" = "apf-policy-service:$app_version"
test "$(yq -r '.spec.template.spec.initContainers[0].image' "$deployment")" = "apf-policy-service:$app_version"

render image-global --set global.image.registry=registry.example.com/apf --set global.image.tag=1.2.3 \
  --set global.image.pullPolicy=Always --set policyGateway.image.tag=2.0.0 --set policyGateway.image.pullPolicy=Never \
  --set 'global.imagePullSecrets[0].name=regcred'
test "$(policy_service '.image')" = registry.example.com/apf/apf-policy-service:1.2.3
test "$(policy_service '.imagePullPolicy')" = Always
test "$(gateway '.image')" = registry.example.com/apf/apf-policy-gateway:2.0.0
test "$(gateway '.imagePullPolicy')" = Never
test "$(yq -r '.spec.template.spec.imagePullSecrets[0].name' "$deployment")" = regcred

digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
render image-digest --set policyService.image.registry=registry.example.com --set policyService.image.tag=ignored \
  --set "policyService.image.digest=$digest"
test "$(policy_service '.image')" = "registry.example.com/apf-policy-service@$digest"
test "$(gateway '.image')" = "apf-policy-gateway:$app_version"

render no-retain --set persistence.state.retain=false
test "$(yq -r '.metadata.annotations' "$statepvc")" = null

render ephemeral-state --set persistence.state.enabled=false
check_file_count 3
test "$(yq -r '.spec.strategy' "$deployment")" = null
test "$(volume state '.emptyDir')" = "{}"

render existing-serviceaccount --set serviceAccount.create=false --set serviceAccount.name=apf-runner
check_file_count 3
test "$(yq -r '.spec.template.spec.serviceAccountName' "$deployment")" = apf-runner

render rollout --set rollout.revision=r2 --set rollout.annotationKey=example.com/revision --set podLabels.team=policy
test "$(yq -r '.spec.template.metadata.annotations["example.com/revision"]' "$deployment")" = r2
test "$(yq -r '.spec.template.metadata.labels.team' "$deployment")" = policy

render http --set policyService.bundle.source=http \
  --set policyService.bundle.http.url=http://example.invalid/bundle.tar.gz
check_egress off
check_source http

render openshift --set openshift=true
test "$(yq -r '.spec.template.spec.securityContext.runAsNonRoot' "$deployment")" = true
test "$(yq -r '.spec.template.spec.securityContext.runAsUser' "$deployment")" = null
test "$(yq -r '.spec.template.spec.securityContext.runAsGroup' "$deployment")" = null
test "$(yq -r '.spec.template.spec.securityContext.fsGroup' "$deployment")" = null

render egress --set policyGateway.openshell.egress.enabled=true \
  --set policyGateway.openshell.egress.tlsSecret=egress-tls
check_egress on
check_source local

render http-egress --set policyService.bundle.source=http \
  --set policyService.bundle.http.url=https://example.invalid/bundle.tar.gz \
  --set policyGateway.openshell.egress.enabled=true --set policyGateway.openshell.egress.tlsSecret=egress-tls \
  --set policyService.prepareResources.requests.cpu=25m --set persistence.audit.emptyDirSizeLimitMi=64
check_egress on
check_source http
test "$(yq -r '.spec.template.spec.initContainers[] | select(.name == "prepare") | .resources.requests.cpu' "$deployment")" = 25m
test "$(volume audit '.emptyDir.sizeLimit')" = 64Mi

test -z "$(gateway '.args[] | select(. == "--pip-config=/etc/apf/pip/pips.yaml")')"
test -z "$(policy_service '.args[] | select(. == "--document-ttl-secs=120")')"
test -z "$(volume pip-config '.name')"

render pip-and-ttl --set policyGateway.pip.configMap=apf-pips --set policyGateway.pip.stageBudgetMs=400 \
  --set policyService.documentTtlSecs=120
test "$(gateway '.args[] | select(. == "--pip-config=/etc/apf/pip/pips.yaml")')" = "--pip-config=/etc/apf/pip/pips.yaml"
test "$(gateway '.args[] | select(. == "--pip-stage-budget-ms=400")')" = "--pip-stage-budget-ms=400"
test "$(gateway '.volumeMounts[] | select(.name == "pip-config") | .mountPath')" = /etc/apf/pip/pips.yaml
test "$(gateway '.volumeMounts[] | select(.name == "pip-config") | .subPath')" = pips.yaml
test "$(gateway '.volumeMounts[] | select(.name == "pip-config") | .readOnly')" = true
test "$(volume pip-config '.configMap.name')" = apf-pips
test "$(volume pip-config '.configMap.items[0].key')" = pips.yaml
test "$(policy_service '.args[] | select(. == "--document-ttl-secs=120")')" = "--document-ttl-secs=120"

render sidecar --set 'extraContainers[0].name=provider-mock' --set 'extraContainers[0].image=example/provider-mock:1'
test "$(yq -r '.spec.template.spec.containers | length' "$deployment")" = 3
test "$(yq -r '.spec.template.spec.containers[2].name' "$deployment")" = provider-mock

render networkpolicy --set networkPolicy.enabled=true \
  --set 'networkPolicy.admissionFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=openshell' \
  --set 'networkPolicy.egressFrom[0].podSelector.matchLabels.role=supervisor' \
  --set policyGateway.openshell.egress.enabled=true --set policyGateway.openshell.egress.tlsSecret=egress-tls
check_file_count 5
test "$(yq -r '.kind' "$networkpolicy")" = NetworkPolicy
test "$(yq -r '.spec.ingress | length' "$networkpolicy")" = 2
test "$(yq -r '.spec.ingress[0].ports[0].port' "$networkpolicy")" = 18081
test "$(yq -r '.spec.ingress[0].from[0].namespaceSelector.matchLabels["kubernetes.io/metadata.name"]' "$networkpolicy")" = openshell
test "$(yq -r '.spec.ingress[1].ports[0].port' "$networkpolicy")" = 9099
test "$(yq -r '.spec.ingress[1].from[0].podSelector.matchLabels.role' "$networkpolicy")" = supervisor

render networkpolicy-admission-only --set networkPolicy.enabled=true \
  --set 'networkPolicy.admissionFrom[0].podSelector.matchLabels.app=openshell'
test "$(yq -r '.spec.ingress | length' "$networkpolicy")" = 1

must_fail misspelled-value --set policyGateway.resorces.requests.cpu=25m
must_fail old-gateway-key --set gateway.image=apf-policy-gateway:dev
must_fail old-state-key --set state.persistence=false
must_fail old-interceptor-key --set policyGateway.openshell.interceptor.port=18081
must_fail old-middleware-key --set policyGateway.openshell.middleware.enabled=true
must_fail old-interceptor-peers-key --set networkPolicy.enabled=true \
  --set 'networkPolicy.interceptorFrom[0].podSelector.matchLabels.app=openshell'
must_fail unknown-global-key --set global.imageRegistry=example.com
must_fail sidecar-not-a-list --set extraContainers=provider-mock
must_fail negative-pip-budget --set policyGateway.pip.configMap=apf-pips --set policyGateway.pip.stageBudgetMs=-1
must_fail unknown-pip-key --set policyGateway.pip.configMapName=apf-pips
must_fail negative-document-ttl --set policyService.documentTtlSecs=-1
must_fail invalid-admission-port --set policyGateway.openshell.admission.port=65536
must_fail invalid-http-port --set policyService.http.port=0
must_fail invalid-audit-limit --set persistence.audit.emptyDirSizeLimitMi=-1
must_fail fractional-audit-limit --set persistence.audit.emptyDirSizeLimitMi=1.5
must_fail invalid-pull-policy --set global.image.pullPolicy=Sometimes
must_fail malformed-digest --set policyGateway.image.digest=sha256:abc
must_fail malformed-digest-no-prefix --set policyGateway.image.digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
must_fail invalid-service-type --set service.type=ExternalName
must_fail admission-http-port-collision --set policyService.http.port=18081
must_fail egress-port-collision --set policyGateway.openshell.egress.enabled=true \
  --set policyGateway.openshell.egress.tlsSecret=egress-tls --set policyGateway.openshell.egress.port=18081
must_fail missing-egress-tls --set policyGateway.openshell.egress.enabled=true
must_fail missing-http-url --set policyService.bundle.source=http
must_fail networkpolicy-without-peers --set networkPolicy.enabled=true
must_fail networkpolicy-without-egress-peers --set networkPolicy.enabled=true \
  --set 'networkPolicy.admissionFrom[0].podSelector.matchLabels.app=openshell' \
  --set policyGateway.openshell.egress.enabled=true --set policyGateway.openshell.egress.tlsSecret=egress-tls

echo 'APF Helm render checks passed'
