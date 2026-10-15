<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deploy APF with OpenShell 0.1.3

Run from the APF repository root. This recipe uses release `openshell-local` in
namespace `openshell`, and release `apf` in namespace `apf` (Service `apf-apf`).
The two charts remain separate; upstream OpenShell has no `apfExtensions` value.
The local commands assume `docker-desktop` is the current Kubernetes context.

## Prerequisites

Use Helm 3, an OpenShell 0.1.3 CLI, a default StorageClass, and a cluster that
enforces ingress and egress NetworkPolicy. Build and publish both APF images
from this revision, or load them into every schedulable node for local testing.
The chart's default image repositories are `apf-policy-service` and
`apf-policy-gateway`; set `global.image.registry` for your registry.

```sh
kubectl create namespace openshell
kubectl create namespace apf
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.3/sandbox.yaml
kubectl -n agent-sandbox-system rollout status deployment/agent-sandbox-controller
```

Provision these external inputs through your secret/policy distribution system.
Keep private material in Vault and out of values files, Git, and command output.

| Namespace | Resource | Required contents |
| --- | --- | --- |
| `openshell` | Secret `openshell-credential-kek` | `key-encryption-key`: a base64-encoded 32-byte encryption key, before Kubernetes Secret encoding. |
| `apf` | ConfigMap `apf-bundle` | `bundle.tar.gz`: a verified signed bundle with `bundle/manifest.yaml` inside it. |
| `apf` | ConfigMap `apf-trust` | `<key-id>.pub`: the matching bundle verification key. |
| `apf` | Secret `apf-runtime` | `document-signing.seed`, `token`, `tls.crt`, `tls.key`, interceptor `trust.toml`. |
| `apf` | Secret `apf-middleware-tls` | `tls.crt`, `tls.key`, middleware `trust.toml`. |
| `openshell` | ConfigMap `apf-listener-ca` | `ca.crt`: the CA for both APF listener certificates. |

The APF certificates must cover `apf-apf.apf.svc.cluster.local`. Prepare the
listener trust profiles after OpenShell has generated its JWT key, as below.

## Prepare the values

Save as **openshell.yaml**. The authentication settings shown are for the local
port-forward test; substitute your existing user authentication for shared use.

```yaml
global:
  image:
    tag: "0.1.3"
pkiInitJob:
  enabled: true
server:
  sandboxJwt:
    signingSecretName: openshell-jwt-keys
    gatewayId: openshell
  credentialStorage:
    existingSecret: openshell-credential-kek
  tls:
    enableMtls: false
  auth:
    allowUnauthenticatedUsers: true
  telemetryEnabled: false
```

Keep PKI bootstrap enabled unless you already provision **all** required TLS
and JWT Secrets. It creates `openshell-jwt-keys` without putting private keys in
Helm values. The explicit `gatewayId` keeps the JWT issuer
`openshell-gateway:openshell` despite the `openshell-local` release name.

Save as **apf.yaml**, replacing the image tag:

```yaml
global:
  image:
    tag: "YOUR_APF_IMAGE_TAG"
policyGateway:
  openshell:
    egress:
      enabled: true
      tlsSecret: apf-middleware-tls
```

For images loaded locally, also set `global.image.pullPolicy: Never`.

## Install OpenShell, then APF

```sh
OPENSHELL_CHART=oci://ghcr.io/nvidia/openshell/helm-chart
helm upgrade --install openshell-local "$OPENSHELL_CHART" --version 0.1.3 \
  -n openshell -f openshell.yaml --wait --timeout 10m
```

Before installing APF, provision both listener trust profiles using the
`public.pem` and `kid` from Secret `openshell/openshell-jwt-keys`. Use issuer
`openshell-gateway:openshell`, `max_lifetime_secs = 3600`, and
`leeway_secs = 60`, with these separate audiences:

- Interceptor: `urn:openshell:extension:interceptor:apf-policy-adapter`
- Middleware: `urn:openshell:extension:middleware:apf-content-policy`

See [trust-profile format](../../../docs/deployment/kubernetes.mdx#trust-profiles).
Once the external APF inputs are present:

```sh
helm lint deploy/helm/apf -f apf.yaml
helm template apf deploy/helm/apf -n apf -f apf.yaml
helm upgrade --install apf deploy/helm/apf \
  -n apf -f apf.yaml --wait --timeout 10m
kubectl -n apf get pods,svc,pvc
kubectl -n apf logs deployment/apf-apf -c policy-gateway
```

## Enable APF in OpenShell

Save as **openshell-apf.yaml**:

```yaml
server:
  extraVolumes:
    - name: apf-listener-ca
      configMap:
        name: apf-listener-ca
  extraVolumeMounts:
    - name: apf-listener-ca
      mountPath: /etc/apf-ca
      readOnly: true
gatewayConfig:
  openshell.gateway:
    provider_profile_sources:
      - type: interceptor
        name: apf/policy-adapter
  openshell.gateway.interceptors:
    - name: apf/policy-adapter
      grpc_endpoint: https://apf-apf.apf.svc.cluster.local:18081
      audience: urn:openshell:extension:interceptor:apf-policy-adapter
      tls_ca_cert_path: /etc/apf-ca/ca.crt
      order: 0
      failure_policy: fail_closed
  openshell.supervisor.middleware:
    - name: apf-content-policy
      grpc_endpoint: https://apf-apf.apf.svc.cluster.local:9099
      audience: urn:openshell:extension:middleware:apf-content-policy
      tls_ca_cert_path: /etc/apf-ca/ca.crt
      max_payload_bytes: 4194304
      timeout: 10s
```

```sh
helm upgrade openshell-local "$OPENSHELL_CHART" --version 0.1.3 \
  -n openshell -f openshell.yaml -f openshell-apf.yaml --wait --timeout 10m
kubectl -n openshell rollout status statefulset/openshell-local
```

Both endpoints must be reachable from the gateway; middleware must also be
reachable from sandbox supervisors. The gateway passes the middleware CA to
supervisors, so they need no separate CA mount.

## Verify locally

Keep this running in one terminal:

```sh
kubectl -n openshell port-forward svc/openshell-local 8080:8080
```

In another terminal:

```sh
export OPENSHELL_GATEWAY_ENDPOINT=https://127.0.0.1:8080
export OPENSHELL_GATEWAY_INSECURE=true
openshell gateway info
openshell settings set --global --key agent_policy_proposals_enabled --value false --yes
openshell sandbox create --name demo
openshell sandbox list
openshell sandbox get demo
openshell sandbox connect demo
```

The insecure flag skips certificate verification for this local test. In each
interactive shell, press **Ctrl-P, Ctrl-Q** to detach and continue the recipe.
To use your workload image, add `--from YOUR_WORKLOAD_IMAGE
--no-auto-providers` to the create command. The default Ubuntu image has no
agent, `curl`, or Python installed.

## Upgrade and recover

Repeat Helm with the same values, keeping `openshell-apf.yaml` on OpenShell
upgrades. After changing external APF TLS, trust, or bundle inputs, change
`rollout.revision` in `apf.yaml` and upgrade APF to reload them. Use
`helm history` and `helm rollback` for release recovery; external Secrets,
policy data, and persistent state are managed separately.
