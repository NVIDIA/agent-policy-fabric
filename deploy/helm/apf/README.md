<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# APF Helm chart

Deploys the APF policy service and policy gateway as two containers in one pod.
The service verifies signed policy bundles and serves policy projections to the
gateway over a Unix socket. The gateway exposes the OpenShell interceptor and,
with `tier: 2`, supervisor middleware. OpenShell itself is deployed separately.

## Prerequisites

- Helm 3 and a Kubernetes cluster. With the default `state.persistence: true`,
  the cluster needs a default StorageClass or `state.storageClass` must be set.
- Images for both APF containers accessible to the cluster. The default image
  names are local build names, **not published images**. The policy-service
  image must include `/bin/sh`, `tar`, and `curl` for the init container and
  readiness probe. The repository's [Dockerfiles](../../../deploy/docker/) provide
  suitable images.
- A signed policy bundle and its matching public trust key. See
  [policy publishing](../../../docs/policy-publishing.md). The chart does not
  ship a policy bundle or signing key.
- The Kubernetes Secrets and ConfigMap named below, provisioned in the release
  namespace before installation. Secret values must stay outside Helm values
  and Git.

| Input | Default resource | Required keys | Used by |
| --- | --- | --- | --- |
| Document signing Secret | `apf-runtime` (`signing.existingSecret`) | `document-signing.seed` (`signing.keyFile`) | Policy service |
| Policy-service HTTP token Secret | `apf-runtime` (`policyService.httpTokenSecret`) | `token` | Policy service |
| Interceptor TLS Secret | `apf-runtime` (`interceptor.tlsSecret`) | `tls.crt`, `tls.key`, `trust.toml` | Gateway interceptor; omitted only for insecure local development |
| Middleware TLS Secret | `middleware.tlsSecret` | `tls.crt`, `tls.key`, `trust.toml` | Gateway middleware when `tier: 2` |
| Bundle HTTP bearer-token Secret | `bundle.http.tokenSecret` | `bundle.http.tokenKey` (`token` by default) | Policy service; optional for public URLs |
| Public trust ConfigMap | `apf-trust` (`trustRoot.existingConfigMap`) | Public keys named by key ID | Policy service |
| Local bundle ConfigMap | `apf-bundle` (`bundle.existingConfigMap`) | `bundle.tar.gz` (`bundle.tarKey`) | Init container in local mode |

The first three Secret roles may use the same Secret or separate Secrets.
The interceptor TLS certificate must cover the Service hostname used by
OpenShell. `trust.toml` configures OpenShell extension-JWT caller verification;
it is distinct from the public bundle-signing trust key. With tier 2, configure
and register the middleware endpoint separately.

## Install with an HTTP bundle

The HTTP source is suitable for a published, signed bundle: APF polls the URL,
verifies new revisions, and updates policy without a Helm upgrade. First
provision the runtime Secrets and public trust ConfigMap in namespace `apf`.
Save this as `apf-values.yaml`, replacing the image and bundle URLs with real
ones:

```yaml
gateway:
  image: registry.example.com/apf-policy-gateway:0.1.0
policyService:
  image: registry.example.com/apf-policy-service:0.1.0
bundle:
  source: http
  http:
    url: https://bundles.example.com/apf/bundle.tar.gz
trustRoot:
  existingConfigMap: apf-trust
interceptor:
  tlsSecret: apf-runtime
signing:
  existingSecret: apf-runtime
```

```sh
helm lint deploy/helm/apf -f apf-values.yaml
helm upgrade --install apf deploy/helm/apf \
  --namespace apf --create-namespace --values apf-values.yaml
```

For a private bundle URL, add `bundle.http.tokenSecret` and, if its key is not
`token`, `bundle.http.tokenKey`. For a private image registry, set
`imagePullSecrets` to existing pull Secret references. Use pinned image tags or
digests for repeatable upgrades. The release above creates Service
`apf-apf.apf.svc.cluster.local`; its default TLS interceptor port is `18081`.
Register that HTTPS endpoint and its issuing CA with OpenShell. Set
`interceptor.gatewayEndpoint` when APF needs to call back to the OpenShell
gateway.

## Use a local bundle

Local mode supports offline and demo deployments. With the defaults, provide
ConfigMap `apf-bundle` containing the signed `bundle.tar.gz` and ConfigMap
`apf-trust` containing the matching public key. Alternatively, set
`bundle.existingConfigMap: ""` and provide a packaged `bundle.file` or pass the
tarball with `--set-file bundle.tarGz=/path/to/bundle.tar.gz`. Do not set both
`bundle.file` and `bundle.tarGz`. The chart unpacks the tarball during pod
initialization and reads `bundle.manifest` inside it. Local bundle changes
require a Helm upgrade or pod restart, depending on how the input is managed.

## Operations

The chart creates one Deployment, one Service, and a state PVC by default. It
uses one replica and `Recreate` when state is persistent so antirollback
counters survive pod replacement. Disabling `state.persistence` makes those
counters ephemeral. Audit files use `emptyDir` unless `audit.persistence` is
enabled; use a PVC or external collection if they must survive pod replacement.

A chart-managed bundle or trust ConfigMap change updates the pod checksum and
rolls the pod. APF polls HTTP bundles in process. Changes to existing Secrets
or ConfigMaps do not automatically roll the pod; change `rolloutRevision` after
rotating a Secret or externally managed trust key. The TLS Secret files are
copied into a memory-backed volume at startup because the current APF loader
rejects Kubernetes Secret symlinks.

## Values

[`values.yaml`](values.yaml) lists the defaults and describes each setting.
Run `helm show values deploy/helm/apf` to inspect them; override values with
`--values` or `--set`. `values.schema.json` validates types and selected
constraints.

Use `gateway.extraArgs` and `policyService.extraArgs` for binary options the
chart does not expose directly. Use `extraEnv` for additional environment
entries, or `extraVolumes` with the corresponding container's
`extraVolumeMounts` for custom files. Avoid duplicate flags, environment
names, and volume names. External Secret managers and OpenShell registration
belong to the deployment environment.
