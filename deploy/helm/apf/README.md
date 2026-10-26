<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# APF Helm chart

Deploys the APF policy service and policy gateway as two containers in one pod.
The service verifies signed policy bundles and serves policy projections to the
gateway over a Unix socket. The gateway exposes two OpenShell-facing features:
sandbox admission (registered in OpenShell as a gateway interceptor), which
injects the signed sandbox policy, validates admission operations, and stamps
provenance; and, with `policyGateway.openshell.egress.enabled`, egress request
policy (registered as supervisor middleware), which evaluates each outbound
request from a sandbox. OpenShell itself is deployed separately.

For the concise two-chart install sequence, see [Deploy APF with OpenShell 0.1.3](INSTALL.md).

## Topology

This chart runs the policy service and the policy gateway as two containers in
one pod sharing a Unix socket, the co-located model. The target deployment
separates them: the policy service runs centrally and serves many gateways over
the network, and each policy gateway runs next to the OpenShell gateway it
governs, or centrally as well when latency and the features in use allow. That
split needs the networked policy-service transport, which does not exist yet,
so this chart does not offer it. The practical consequences: the Deployment has
one replica and uses `Recreate`, one state PVC holds the antirollback counters,
and the sandbox admission and egress request policy listeners are the pod's
only network surfaces.

## Prerequisites

- Helm 3 and a Kubernetes cluster. With the default `persistence.state.enabled:
  true`, the cluster needs a default StorageClass or
  `persistence.state.storageClass` must be set.
- Images for both APF containers accessible to the cluster. The default
  repositories are local build names, **not published images**; set
  `global.image.registry` or the per-component `image.registry` and pin a tag
  or digest. The policy-service image must include `/bin/sh`, `tar`, and `curl`
  for the init container and readiness probe. The repository's
  [Dockerfiles](../../../deploy/docker/) provide suitable images.
- A signed policy bundle and its matching public trust key. See
  [Publish and Distribute Bundles](../../../docs/manage-policy-bundles/publish-and-distribute.mdx). The chart does not
  ship a policy bundle or signing key. `apf-compile compile --verify-only
  --bundle-path <manifest> --trust-root-dir <dir> --key-id <id>` runs the same
  verification as the policy service, so a bundle can be checked against its
  trust key before it is placed in the ConfigMap.
- The Kubernetes Secrets and ConfigMaps below, provisioned in the release
  namespace before installation. Every value that names one is marked
  `(prerequisite)` in `values.yaml`. Secret values must stay outside Helm
  values and Git.

| Input | Default resource | Required keys | Used by |
| --- | --- | --- | --- |
| Document signing Secret | `apf-runtime` (`policyService.signing.existingSecret`) | `document-signing.seed` (`policyService.signing.keyFile`) | Policy service |
| Policy-service HTTP token Secret | `apf-runtime` (`policyService.http.tokenSecret`) | `token` | Policy service |
| Sandbox admission TLS Secret | `apf-runtime` (`policyGateway.openshell.admission.tlsSecret`) | `tls.crt`, `tls.key`, `trust.toml` | Gateway sandbox admission listener; omitted only for insecure local development |
| Egress request policy TLS Secret | `policyGateway.openshell.egress.tlsSecret` | `tls.crt`, `tls.key`, `trust.toml` | Gateway egress request policy listener when enabled |
| Bundle HTTP bearer-token Secret | `policyService.bundle.http.tokenSecret` | `policyService.bundle.http.tokenKey` (`token` by default) | Policy service; optional for public URLs |
| Public trust ConfigMap | `apf-trust` (`policyService.trustRoot.existingConfigMap`) | Public keys named by key ID | Policy service |
| Local bundle ConfigMap | `apf-bundle` (`policyService.bundle.local.existingConfigMap`) | `bundle.tar.gz` (`policyService.bundle.local.tarKey`) | Init container in local mode |
| Provider registration ConfigMap | `policyGateway.pip.configMap` | `pips.yaml` (`policyGateway.pip.key`) | Gateway enrichment; optional |
| Image pull Secrets | `global.imagePullSecrets` | | Every container; optional |

The first three Secret roles may use the same Secret or separate Secrets.
The sandbox admission TLS certificate must cover the Service hostname used by
OpenShell. `trust.toml` configures OpenShell extension-JWT caller verification;
it is distinct from the public bundle-signing trust key. Give egress request
policy its own TLS Secret: its `trust.toml` has a different audience from the
sandbox admission one.

## Install with an HTTP bundle

The HTTP source is suitable for a published, signed bundle: APF polls the URL,
verifies new revisions, and updates policy without a Helm upgrade. First
provision the runtime Secrets and public trust ConfigMap in namespace `apf`.
Save this as `apf-values.yaml`, replacing the registry and bundle URL with real
ones:

```yaml
global:
  image:
    registry: registry.example.com/apf
    tag: 0.1.0
policyService:
  bundle:
    source: http
    http:
      url: https://bundles.example.com/apf/bundle.tar.gz
```

```sh
helm lint deploy/helm/apf -f apf-values.yaml
helm upgrade --install apf deploy/helm/apf \
  --namespace apf --create-namespace --values apf-values.yaml
```

For a private bundle URL, add `policyService.bundle.http.tokenSecret`. For a
private image registry, set `global.imagePullSecrets`. The release above
creates Service `apf-apf.apf.svc.cluster.local`; its default sandbox admission
port is `18081` and, with egress request policy enabled, its egress port is
`9099`, both TLS. Set `policyGateway.openshell.gatewayEndpoint` when APF needs
to call back to the OpenShell gateway.

## Register with the OpenShell gateway

OpenShell is deployed by its own chart
(`oci://ghcr.io/nvidia/openshell/helm-chart`, 0.1.3 or later). This chart
only runs APF; the OpenShell side is a values overlay on that chart. The
gateway calls `Describe` on every registered extension at startup and fails
closed when one is unreachable, so the order is: install OpenShell without
the registration, read its JWT Secret, install APF and wait for the pod to be
Ready, then `helm upgrade` OpenShell with the overlay below.
[`e2e/with-kind-stack.sh`](../../../e2e/README.md) runs that sequence end to end on a kind cluster.

### Trust files from the OpenShell JWT Secret

OpenShell's certgen Job writes Secret `<fullname>-jwt-keys` with keys
`public.pem` and `kid`. The extension-JWT issuer is
`openshell-gateway:<gateway_id>`, where `gateway_id` defaults to the OpenShell
chart fullname (`openshell` for release `openshell`). Each APF listener gets
its own `trust.toml` with the audience it is registered under; the audience
strings are OpenShell's extension type names, `interceptor` for sandbox
admission and `middleware` for egress request policy:

```sh
kubectl -n openshell get secret openshell-jwt-keys -o jsonpath='{.data.public\.pem}' | base64 -d > public.pem
kid=$(kubectl -n openshell get secret openshell-jwt-keys -o jsonpath='{.data.kid}' | base64 -d)
for surface in interceptor middleware; do
  cat > "trust-$surface.toml" <<EOF
issuer = "openshell-gateway:openshell"
audience = "urn:openshell:extension:$surface:openshell"
kid = "$kid"
public_key_pem = """
$(cat public.pem)
"""
max_lifetime_secs = 3600
leeway_secs = 60
EOF
done
```

Put `trust-interceptor.toml` as `trust.toml` in
`policyGateway.openshell.admission.tlsSecret` next to that listener's
`tls.crt` and `tls.key`, and `trust-middleware.toml` in
`policyGateway.openshell.egress.tlsSecret` when egress request policy is
enabled. The serving certificate's SAN must cover
`<release>-apf.<namespace>.svc.cluster.local`.

### OpenShell values overlay

Create a ConfigMap in the OpenShell namespace holding the CA that issued the
APF serving certificate, for example `kubectl -n openshell create configmap
apf-ca --from-file=ca.crt`. Then upgrade OpenShell with these values, keeping
the `audience` strings identical to the `trust.toml` files above. The stanza
keys are OpenShell's own: sandbox admission registers under
`openshell.gateway.interceptors` and egress request policy under
`openshell.supervisor.middleware`. The gateway embeds the CA into the
registration it sends to supervisors, so only the gateway pod needs the mount.
Omit the `openshell.supervisor.middleware` stanza when
`policyGateway.openshell.egress.enabled` is false.

```yaml
server:
  extraVolumes:
    - name: apf-ca
      configMap:
        name: apf-ca
  extraVolumeMounts:
    - name: apf-ca
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
      audience: urn:openshell:extension:interceptor:openshell
      tls_ca_cert_path: /etc/apf-ca/ca.crt
      order: 0
      failure_policy: fail_closed
  openshell.supervisor.middleware:
    - name: apf-content-policy
      grpc_endpoint: https://apf-apf.apf.svc.cluster.local:9099
      audience: urn:openshell:extension:middleware:openshell
      tls_ca_cert_path: /etc/apf-ca/ca.crt
      max_payload_bytes: 4194304
      timeout: 10s
```

```sh
helm upgrade openshell oci://ghcr.io/nvidia/openshell/helm-chart --version 0.1.3 \
  --namespace openshell --reuse-values --values openshell-apf.yaml
```

`provider_profile_sources` with only the APF entry makes APF's projected
provider catalog authoritative; add `{ type: user }` to compose imported
profiles with it. The chart's post-install notes print this overlay with the
release's actual Service DNS name and ports.

## Use a local bundle

Local mode supports offline and demo deployments. With the defaults, provide
ConfigMap `apf-bundle` containing the signed `bundle.tar.gz` and ConfigMap
`apf-trust` containing the matching public key. Alternatively, set
`policyService.bundle.local.existingConfigMap: ""` and provide a packaged
`policyService.bundle.local.file` or pass the tarball with `--set-file
policyService.bundle.local.tarGz=/path/to/bundle.tar.gz`, but not both. The
chart unpacks the tarball during pod initialization and reads the manifest
inside it. Local bundle changes require a Helm upgrade or pod restart,
depending on how the input is managed.

## Operations

The chart creates one Deployment with one replica, one Service, one
ServiceAccount, and a state PVC by default. A chart-managed bundle or trust
ConfigMap change updates the pod checksum and rolls the pod. APF polls HTTP
bundles in process. Changes to existing Secrets or ConfigMaps do not roll the
pod; change `rollout.revision` after rotating a Secret, an externally managed
trust key, or the provider registration. The TLS Secret files are copied into
a memory-backed volume at startup because the current APF loader rejects
Kubernetes Secret symlinks.

Set `policyGateway.resources`, `policyService.resources`, and
`policyService.prepareResources` from measured workload usage; the chart leaves
them unset. Gateway readiness checks the sandbox admission TCP port, or the
egress request policy TCP port when that feature is enabled; it does not test
TLS authentication or policy decisions. An exhausted audit volume can block
policy operations, so bound the audit `emptyDir` or give it a PVC.

### Rotate listener TLS and OpenShell JWT trust

Provision changed `tls.crt`, `tls.key`, or `trust.toml` files in each affected
listener's Secret. Wait until Kubernetes has the updated Secret, then change
the nonsecret `rollout.revision` value and upgrade the release. Verify the
replacement pod is ready, the certificate on a new TLS connection, a fresh
sandbox admission, and, with egress request policy enabled, an outbound
request from a sandbox. With the default persistent state, this restarts the
sole pod using `Recreate` and briefly interrupts APF.

For a certificate renewal under the same CA, keep the certificate valid for
the hostname in OpenShell's endpoint. For a CA change, coordinate OpenShell's
`tls_ca_cert_path` with the certificate rollout; OpenShell must trust the CA
presented by APF when it reconnects.

For an OpenShell extension-JWT signing-key change, update each listener's
`trust.toml` with the gateway's new public key and `kid` before rolling APF.
Its `issuer` and exact `audience` must match the OpenShell registration, and
`max_lifetime_secs` must cover OpenShell's configured token lifetime without
exceeding 3600. Each listener accepts only one key, so coordinate the APF
rollout with OpenShell's signer switch; this version cannot overlap old and new
JWT signing keys. APF stores only the public key. This trust is separate from
the policy service's document-provenance JWKS and bundle-signing trust. See
[Configure Service Authentication](../../../docs/deployment/configure-service-authentication.mdx)
for the trust-profile format and caller rules.

## Values

[`values.yaml`](values.yaml) is the reference: every key carries a one-line
comment, and keys naming objects created outside the chart are marked
`(prerequisite)`. Run `helm show values deploy/helm/apf` to read it; override
with `--values` or `--set`. `values.schema.json` rejects unknown keys, wrong
types, out-of-range ports and counters, and malformed image digests.

On by default, because the chart can provide them alone:

- hardened security contexts: non-root UID/GID, `RuntimeDefault` seccomp,
  read-only root filesystems, all capabilities dropped, no ServiceAccount token
  mounted;
- a dedicated ServiceAccount, so NetworkPolicies and admission rules can name
  the pod;
- `Recreate` with a retained state PVC (`helm.sh/resource-policy: keep`), so
  antirollback counters survive pod replacement and release removal;
- the policy-input checksum and `rollout.revision` annotations on the pod
  template;
- readiness probes on the policy-service `/readyz` route and the gateway
  listener port;
- schema validation of the values.

Off by default, because each needs something outside the chart:

- `networkPolicy`: the OpenShell gateway and supervisor peers to admit;
- `persistence.audit`: a PVC-backed audit directory or an external collector;
- `policyGateway.openshell.egress`: a second TLS Secret and the OpenShell
  supervisor middleware registration;
- `policyGateway.pip`: a provider registration ConfigMap and the providers it
  names, for example a loopback sidecar in `extraContainers`;
- `policyService.bundle.source: http`: a bundle URL and, for private URLs, a
  token Secret;
- `policyGateway.openshell.gatewayEndpoint`: the OpenShell gateway URL for
  callbacks;
- `openshift`: OpenShift-assigned UID and GID;
- `policyGateway.openshell.admission.allowInsecureTransport`: an isolated
  development network.

Use `policyGateway.extraArgs` and `policyService.extraArgs` for binary options
the chart does not expose directly, `extraEnv` for additional environment
entries, and `extraVolumes` with the corresponding container's
`extraVolumeMounts` for custom files. `extraContainers` adds sidecars to the
pod; the gateway accepts plain-`http` provider URLs only on loopback, so a
policy information provider that is not served over HTTPS must run as such a
sidecar and be registered at `http://127.0.0.1:<port>`. Avoid duplicate flags,
environment names, container names, and volume names. External Secret managers
and OpenShell registration belong to the deployment environment.

## Packaging and OCI distribution

```sh
helm package deploy/helm/apf --destination dist/helm
helm push dist/helm/apf-0.6.0.tgz oci://registry.example.com/team/charts
helm upgrade --install apf oci://registry.example.com/team/charts/apf \
  --version 0.6.0 -n apf --create-namespace -f apf-values.yaml
```

`helm package --version <chart-version> --app-version <image-tag>` stamps
release versions without changing source. Use an application version published
for both service images. Packaging includes the license, generated README,
values schema, and runtime templates, and excludes development/test files.

The chart's `LICENSE` is a symbolic link to the repository's root `LICENSE`,
so install or package the chart from a repository checkout. To copy the chart
elsewhere, use `cp -RL` so the copy holds the license text rather than the
link; Helm refuses to load a chart whose `LICENSE` link points nowhere.

## Chart validation

```sh
sh deploy/helm/apf/tests/render.sh
helm lint --strict deploy/helm/apf
helm-docs --chart-search-root deploy/helm/apf
helm unittest deploy/helm/apf
```

The [verification harness](../../../e2e/README.md) covers the integrated kind
deployment, including the optional provider lane.

## Values reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Pod affinity rules. |
| extraContainers | list | `[]` | Sidecar containers appended to the pod, such as a loopback policy information provider. |
| extraVolumes | list | `[]` | Volumes appended to the pod. |
| fullnameOverride | string | `""` | Replaces the release-derived resource name. |
| global.image.pullPolicy | string | `"IfNotPresent"` | Shared image pull policy; a component pull policy takes precedence. |
| global.image.registry | string | `""` | Shared image registry; a component registry takes precedence. |
| global.image.tag | string | `""` | Shared image tag; a component tag takes precedence. Empty uses the chart appVersion. |
| global.imagePullSecrets | list | `[]` | Image pull Secret references for every container in the pod (prerequisite). |
| nameOverride | string | `""` | Replaces the chart name in resource names and labels. |
| networkPolicy.admissionFrom | list | `[]` | Sandbox admission (OpenShell gateway interceptor): NetworkPolicyPeer entries allowed to reach its port. |
| networkPolicy.egressFrom | list | `[]` | Egress request policy (OpenShell supervisor middleware): NetworkPolicyPeer entries allowed to reach its port. |
| networkPolicy.enabled | bool | `false` | Creates a NetworkPolicy admitting ingress to the listeners only from the peers below. |
| nodeSelector | object | `{}` | Node labels the pod must match. |
| openshift | bool | `false` | Omits explicit UID and GID so OpenShift assigns them. |
| persistence.audit.emptyDirSizeLimitMi | int | `0` | Size limit of the audit emptyDir in MiB; 0 leaves it unbounded. |
| persistence.audit.enabled | bool | `false` | Creates a PVC for audit files; false uses emptyDir. |
| persistence.audit.mountPath | string | `"/var/log/apf/audit"` | Audit directory mounted in both containers. |
| persistence.audit.size | string | `"1Gi"` | Capacity request of the audit PVC. |
| persistence.audit.storageClass | string | `""` | StorageClass of the audit PVC; empty uses the cluster default. |
| persistence.state.enabled | bool | `true` | Creates a PVC for antirollback counters; false uses emptyDir and loses them on pod replacement. |
| persistence.state.retain | bool | `true` | Keeps the state PVC when the release is uninstalled. |
| persistence.state.size | string | `"1Gi"` | Capacity request of the state PVC. |
| persistence.state.storageClass | string | `""` | StorageClass of the state PVC; empty uses the cluster default. |
| podAnnotations | object | `{}` | Annotations on the pod template. |
| podLabels | object | `{}` | Labels on the pod template. |
| podSecurityContext.fsGroup | int | `65532` | Pod filesystem group; applied unless openshift is true. |
| podSecurityContext.runAsGroup | int | `65532` | Pod group ID; applied unless openshift is true. |
| podSecurityContext.runAsUser | int | `65532` | Pod user ID; applied unless openshift is true. |
| policyGateway.document.kind | string | `"openshell.sandbox.v1"` | Signed document kind the gateway requests. |
| policyGateway.document.name | string | `"default"` | Signed document name the gateway requests. |
| policyGateway.extraArgs | list | `[]` | Arguments appended after the chart-managed flags. |
| policyGateway.extraEnv | list | `[]` | Environment variable entries appended to the container. |
| policyGateway.extraVolumeMounts | list | `[]` | Volume mounts appended to the container. |
| policyGateway.image.digest | string | `""` | Policy gateway image digest. When set, this takes precedence over tag. |
| policyGateway.image.pullPolicy | string | `nil` | Policy gateway image pull policy. Null uses global.image.pullPolicy. |
| policyGateway.image.registry | string | `""` | Policy gateway image registry. Empty uses global.image.registry. |
| policyGateway.image.repository | string | `"apf-policy-gateway"` | Policy gateway image repository; the default is a local build name. |
| policyGateway.image.tag | string | `""` | Policy gateway image tag. Empty uses the chart appVersion. |
| policyGateway.openshell.admission.allowInsecureTransport | bool | `false` | Sandbox admission (OpenShell gateway interceptor): serves the listener without TLS; isolated local development only. |
| policyGateway.openshell.admission.port | int | `18081` | Sandbox admission (OpenShell gateway interceptor): Service and container port of its listener. |
| policyGateway.openshell.admission.tlsSecret | string | `"apf-runtime"` | Sandbox admission (OpenShell gateway interceptor): Secret with tls.crt, tls.key, and trust.toml (prerequisite). |
| policyGateway.openshell.egress.enabled | bool | `false` | Egress request policy (OpenShell supervisor middleware): exposes its listener. |
| policyGateway.openshell.egress.port | int | `9099` | Egress request policy (OpenShell supervisor middleware): Service and container port of its listener. |
| policyGateway.openshell.egress.tlsSecret | string | `""` | Egress request policy (OpenShell supervisor middleware): Secret with tls.crt, tls.key, and trust.toml (prerequisite); required when enabled. |
| policyGateway.openshell.gatewayEndpoint | string | `""` | OpenShell gateway URL for outbound callbacks; empty makes none. |
| policyGateway.pip.configMap | string | `""` | ConfigMap holding the policy information provider registration (prerequisite); empty disables enrichment. |
| policyGateway.pip.key | string | `"pips.yaml"` | Registration file key in that ConfigMap. |
| policyGateway.pip.stageBudgetMs | int | `0` | Cap on the enrichment stage in milliseconds; 0 keeps the binary default. |
| policyGateway.resources | object | `{}` | CPU and memory requests and limits for the policy gateway container. |
| policyService.bundle.http.pollIntervalSeconds | int | `30` | Seconds between polls of the URL. |
| policyService.bundle.http.tokenKey | string | `"token"` | Token key in that Secret. |
| policyService.bundle.http.tokenSecret | string | `""` | Secret holding a bearer token for the URL (prerequisite); empty sends none. |
| policyService.bundle.http.url | string | `""` | Signed tarball URL; required when source is http. |
| policyService.bundle.local.existingConfigMap | string | `"apf-bundle"` | ConfigMap holding the signed tarball (prerequisite). Empty creates one from tarGz or file. |
| policyService.bundle.local.file | string | `""` | Tarball path packaged inside the chart when existingConfigMap is empty. |
| policyService.bundle.local.manifest | string | `"bundle/manifest.yaml"` | Manifest path inside the extracted tarball. |
| policyService.bundle.local.tarGz | string | `""` |  |
| policyService.bundle.local.tarKey | string | `"bundle.tar.gz"` | Tarball key in the bundle ConfigMap. |
| policyService.bundle.source | string | `"local"` | Signed bundle source: local loads one tarball from a ConfigMap, http polls a URL. |
| policyService.documentTtlSecs | int | `0` | Signed document lifetime in seconds; 0 keeps the binary default. |
| policyService.extraArgs | list | `[]` | Arguments appended after the chart-managed flags. |
| policyService.extraEnv | list | `[]` | Environment variable entries appended to the container. |
| policyService.extraVolumeMounts | list | `[]` | Volume mounts appended to the container. |
| policyService.http.port | int | `19200` | Loopback HTTP port serving readiness and JWKS. |
| policyService.http.tokenSecret | string | `"apf-runtime"` | Secret with key token for protected HTTP routes (prerequisite). |
| policyService.image.digest | string | `""` | Policy service image digest. When set, this takes precedence over tag. |
| policyService.image.pullPolicy | string | `nil` | Policy service image pull policy. Null uses global.image.pullPolicy. |
| policyService.image.registry | string | `""` | Policy service image registry. Empty uses global.image.registry. |
| policyService.image.repository | string | `"apf-policy-service"` | Policy service image repository; the default is a local build name. |
| policyService.image.tag | string | `""` | Policy service image tag. Empty uses the chart appVersion. |
| policyService.prepareResources | object | `{}` | CPU and memory requests and limits for the prepare init container. |
| policyService.resources | object | `{}` | CPU and memory requests and limits for the policy service container. |
| policyService.signing.existingSecret | string | `"apf-runtime"` | Secret holding the document signing seed (prerequisite). |
| policyService.signing.keyFile | string | `"document-signing.seed"` | Key of the signing seed in that Secret. |
| policyService.signing.keyId | string | `"apf"` | Key ID attached to signed documents. |
| policyService.surfaces | list | `["openshell.sandbox.v1","openshell.provider-profile.v1","apf.policy.v1"]` | Policy projection surfaces the service compiles. |
| policyService.trustRoot.existingConfigMap | string | `"apf-trust"` | ConfigMap of public bundle-signing keys (prerequisite). Empty creates one from keys. |
| policyService.trustRoot.keys | object | `{}` | Public keys by key ID for a chart-created ConfigMap; never private keys. |
| rollout.annotationKey | string | `"apf-rollout-revision"` | Pod annotation carrying the revision. |
| rollout.revision | string | `""` | Any string; change it to restart the pod after an external Secret or ConfigMap changes. |
| service.annotations | object | `{}` | Annotations on the Service. |
| service.type | string | `"ClusterIP"` | Kubernetes Service type. |
| serviceAccount.annotations | object | `{}` | Annotations on the created ServiceAccount. |
| serviceAccount.create | bool | `true` | Creates a ServiceAccount for the pod; its token is never mounted. |
| serviceAccount.name | string | `""` | ServiceAccount name; empty derives it from the release, or names an existing one when create is false. |
| tolerations | list | `[]` | Pod tolerations. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
