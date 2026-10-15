<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# APF chart verification harness

Brings the APF chart up on a local kind cluster next to a real OpenShell
gateway and checks that OpenShell admits a sandbox through APF. OpenShell is a
fixture of this harness, not a deliverable of the chart: the chart stays
APF-only and the files here install and register OpenShell only to exercise it.

What one run does:

1. creates kind cluster `apf-e2e`, installs agent-sandbox, and loads the APF,
   OpenShell, sandbox, and pip-stub images into the cluster;
2. installs OpenShell 0.1.3 as a plaintext development gateway with no
   extensions;
3. builds the materials: two signed revisions of the policy bundle, a
   self-signed APF serving certificate, the OpenShell extension-JWT trust
   profiles, and the Secrets and ConfigMaps the chart expects;
4. installs the APF chart from this repository with `apf-values.yaml`; when
   PIP is enabled, `apf-values-pip.yaml` adds a loopback provider stub as a
   sidecar in the APF pod behind the policy information provider registration;
5. upgrades OpenShell with the registration overlay so the gateway uses APF for
   sandbox admission (as a gateway interceptor), egress request policy (as
   supervisor middleware), and as its provider-profile source;
6. runs the smoke checks.

## Quick start

The steps before `up.sh` are done once, offline, on the workstation. Commands
are relative to the repository root.

1. Install the tools: Docker Desktop (or another Docker engine the `docker`
   CLI reaches), `kind`, `kubectl`, `helm` 3, `yq` v4, `openssl`, `python3`,
   and `tar`. On macOS: `brew install kind kubectl helm yq`.
2. Build the two APF images from the repository Dockerfiles. The harness never
   pulls them; it loads them into kind and installs with `pullPolicy: Never`.

   ```sh
   docker build -f deploy/docker/apf-policy-service/Dockerfile --target runtime -t apf-policy-service:dev .
   docker build -f deploy/docker/apf-policy-gateway/Dockerfile -t apf-policy-gateway:dev .
   ```

3. Build the bundle signing tool: `cargo build --release -p apf-compile`.
   `materials.sh` runs this for you when `target/release/apf-compile` is
   missing.
4. Get the OpenShell CLI that matches the OpenShell under test (0.1.3): download
   `openshell-<arch>-<os>.tar.gz` from the OpenShell GitHub release, unpack it,
   and either put `openshell` on `PATH`, set `OPENSHELL_CLI=/path/to/openshell`,
   or drop the binary at `deploy/helm/e2e/.work/openshell`.
5. Make sure the workstation can reach `ghcr.io` (OpenShell chart and images),
   `nvcr.io` (default sandbox image), `github.com` (agent-sandbox manifest), and
   Docker Hub (`python:3.12-slim` for the pip-stub sidecar).
6. Bring everything up and run the checks:

   ```sh
   deploy/helm/e2e/up.sh
   ```

   The first run takes about ten minutes, most of it image loading and the
   OpenShell certgen Job. `up.sh` prints the OpenShell version under test next
   to the OpenShell release APF's protos are pinned to; they may differ as long
   as the extension protocol major version matches, and step 5 fails if the
   gateway cannot negotiate with APF.

7. Look around, then tear down:

   ```sh
   kubectl --context kind-apf-e2e get pods -A
   deploy/helm/e2e/down.sh            # uninstall both releases, delete namespaces
   deploy/helm/e2e/down.sh --cluster  # also delete the kind cluster
   ```

Other entry points:

```sh
deploy/helm/e2e/up.sh --skip-cluster  # reuse an existing cluster and images
deploy/helm/e2e/smoke.sh              # checks only, against a running stack
deploy/helm/e2e/up.sh --render-only   # write the environment-adjusted values into .work and stop
```

## Install order

The OpenShell gateway calls `Describe` on every registered extension at startup
and fails closed when one is unreachable, and APF needs OpenShell's extension-JWT
public key before it can verify callers. Both constraints fix the order:

1. OpenShell first, without extensions. Its certgen pre-install Job creates
   Secret `openshell-jwt-keys` (`public.pem`, `kid`), which `materials.sh` reads
   into the APF `trust.toml` files.
2. APF second, once the trust profiles, the serving certificate, the signed
   bundle, and the trust root exist. `up.sh` waits for the Deployment to be
   Ready.
3. OpenShell again with `openshell-values-apf.yaml`, which adds the sandbox
   admission, egress request policy, and provider-profile-source stanzas under
   OpenShell's own keys (`openshell.gateway.interceptors`,
   `openshell.supervisor.middleware`) and mounts the APF certificate from
   ConfigMap `apf-ca` at `/etc/apf-ca/ca.crt`. The gateway embeds that CA in
   the egress request policy registration it hands to supervisors, so sandboxes
   need no mount.

Trust between the two is symmetric: APF trusts OpenShell's JWT key with issuer
`openshell-gateway:openshell` and one audience per listener, named by
OpenShell's extension type (`urn:openshell:extension:interceptor:openshell`
for sandbox admission, `urn:openshell:extension:middleware:openshell` for
egress request policy); OpenShell trusts the APF certificate, whose SANs cover
`apf.apf.svc.cluster.local` and its short forms.

## Signing and verification

`materials.sh` signs the bundle the way a policy pipeline does and shows the
result:

1. `apf-compile genfixture` hashes every member file listed in the template,
   replaces the `sha256: REPLACE_WITH_DIGEST` placeholders with the real
   digests, and signs the whole document with the Ed25519 seed. It prints one
   line per member (`manifest  sandbox/default-policy.yaml: sha256=…`) and
   writes `manifest.yaml`, which ends with the signature carrier:

   ```yaml
   schema: YamlSigilSignature.v1alpha1
   alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
   keyid: "apf-dev"
   signature: …
   ```

   `keyid` must equal the file stem of the public key in the trust ConfigMap
   (`apf-dev` ↔ `apf-dev.pub`); that is how the policy service finds the key to
   verify with.
2. The harness then runs the same verification the policy service runs at
   startup, offline:

   ```sh
   target/release/apf-compile compile --verify-only \
     --bundle-path deploy/helm/e2e/.work/bundle-v1/bundle/manifest.yaml \
     --trust-root-dir examples/dev-keys --key-id apf-dev
   # verified  digest=<sha256 of manifest.yaml> counter=1
   ```

   and records the document's sha256 in `.work/bundle-v1.digest`.
3. In the cluster, the policy service logs
   `bundle verified and loaded path=/data/bundles/bundle/manifest.yaml digest=<sha256> counter=1`;
   `smoke.sh` compares that digest with the recorded one, so the run proves the
   pod verified exactly the document the harness signed. The sandbox then
   carries `apf.nvidia.com/signer-identity: apf-dev` and a provenance token
   minted by the policy service.

To see verification refuse a change made after signing, edit any member of a
staged bundle and verify again:

```sh
cp -R deploy/helm/e2e/.work/bundle-v1/bundle /tmp/tampered
printf '\n# edited after signing\n' >> /tmp/tampered/provider-profiles/github.yaml
target/release/apf-compile compile --verify-only --bundle-path /tmp/tampered/manifest.yaml \
  --trust-root-dir examples/dev-keys --key-id apf-dev
# Error: verification failed: ["manifest_hash_mismatch: provider-profiles/github.yaml: declared …, actual …"]
```

The policy service refuses such a bundle the same way at startup, and the
OpenShell gateway, registered fail-closed, then admits no sandbox.

## Smoke checks

`smoke.sh` prints `ok` or `FAIL` per check and exits non-zero if any failed:

1. APF Deployment Ready, and the policy service's `bundle verified and loaded`
   digest equals the sha256 of the document `materials.sh` signed.
2. Sandbox admission and egress request policy are registered: `gateway.toml`
   in ConfigMap `openshell-config` names the `apf/policy-adapter` interceptor,
   the `apf-content-policy` middleware, and the `apf/policy-adapter`
   provider-profile source, and the gateway StatefulSet is rolled out. The
   gateway fails closed at startup when `Describe` on an extension fails, so a
   Ready gateway proves the negotiation; its startup log only counts bindings.
3. `openshell gateway info` succeeds through a `kubectl port-forward` to the
   gateway Service.
4. Sandbox admission: `openshell sandbox create --name apf-e2e --detach --
   sleep 3600` succeeds and the sandbox carries the `apf.nvidia.com/bundle-id`
   and `apf.nvidia.com/provenance-token` annotations (printed).
5. Sandbox admission: the gateway log records a `gateway interceptor
   evaluated` line with `interceptor=apf/policy-adapter` for that admission.
6. Sandbox admission: the audit file in the APF pod records an
   `interceptor.policy_injected` event.
7. With PIP enabled: the pip-stub sidecar is Ready and
   `GET http://127.0.0.1:19500/healthz` (`PIP_STUB_HEALTH_PATH`) from inside
   the APF pod returns 200.

Egress request policy is registered but not exercised: the test sandbox makes
no outbound request.

The test sandbox is deleted at the end unless `KEEP_SANDBOX=1`.

## Files

| File | Role |
| --- | --- |
| `env.sh` | Shared variables, defaults, and helpers (`kctl`, `helmk`, `wait_for_rollout`, `dump_cluster_state`) |
| `kind.sh` | `up`, `down`, `status` for the kind cluster, agent-sandbox, and image loading |
| `openshell-values.yaml` | OpenShell fixture: plaintext gateway, unauthenticated users, certgen Job on |
| `openshell-values-apf.yaml` | OpenShell registration overlay for APF plus the `apf-ca` mount |
| `apf-values.yaml` | APF chart values for the run (sandbox admission and egress request policy enabled, local bundle, external Secrets and ConfigMaps) |
| `apf-values-pip.yaml` | Provider-enrichment values (`policyGateway.pip` plus the pip-stub sidecar through `extraContainers`), layered only when PIP is enabled |
| `fixtures/pip/pips.yaml`, `fixtures/pip/stub.py` | Minimal provider registration and the loopback stub behind it; they prove the chart wires `policyGateway.pip.*` and `extraContainers` |
| `materials.sh` | Builds and applies bundles, certificate, trust profiles, Secrets, ConfigMaps; `bundle v1\|v2` swaps the bundle ConfigMap |
| `up.sh` | Orchestration with per-step logs and failure dumps |
| `down.sh` | Teardown |
| `smoke.sh` | Assertions |

The checked-in values files assume the default names (release `openshell`,
APF Service `apf` in namespace `apf`, chart default ports). `up.sh` rewrites
endpoints, audiences, image tags, and ports from the environment into
`E2E_WORK` before use, so changing a knob below does not require editing them.

## Work directory, logs, and materials

Everything generated lands in `E2E_WORK` (default `deploy/helm/e2e/.work`,
gitignored):

- `bundle-v1/`, `bundle-v2/`, `bundle-v1.tar.gz`, `bundle-v2.tar.gz`: staged and
  signed bundle revisions; the tarball root is `bundle/` with `manifest.yaml`
  and the members. Revision 2 is revision 1 with `policy_revision: 2`, plus
  whatever `BUNDLE_V2_TRANSFORM` changes.
- `tls/apf.crt`, `tls/apf.key`: the APF serving certificate (RSA 2048,
  365 days, `CA:FALSE`, `serverAuth`).
- `openshell-jwt-public.pem`, `openshell-jwt-kid`, `trust-interceptor.toml`,
  `trust-middleware.toml`: OpenShell extension-JWT trust, one profile per
  listener (sandbox admission, egress request policy), named by OpenShell's
  extension type.
- `http-bearer-token`: the policy-service HTTP token, generated once.
- `pips.yaml`: the provider registration as loaded by the gateway; its
  loopback URL is served by the pip-stub sidecar.
- `openshell-values.yaml`, `openshell-values-apf.yaml`, `apf-values.yaml`:
  environment-adjusted copies of the checked-in values.
- `logs/<step>.log`: the output of every `up.sh` step; `logs/` also holds the
  rendered `gateway.toml`, gateway log, sandbox JSON, and audit tail saved by
  `smoke.sh`.
- `charts/`: a local copy of the OpenShell chart when pulled for inspection.

Cluster-side materials: Secrets `apf-runtime` (signing seed, HTTP token, TLS,
sandbox admission `trust.toml`) and `apf-egress` (TLS, egress request policy
`trust.toml`), ConfigMaps `apf-trust`, `apf-bundle`, `apf-pip`, `apf-pip-stub`
in the APF namespace, and ConfigMap `apf-ca` in the OpenShell namespace.

To swap the bundle to revision 2 and restart APF:

```sh
deploy/helm/e2e/materials.sh bundle v2
kubectl --context kind-apf-e2e -n apf rollout restart deployment/apf
```

## Environment knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `KIND_CLUSTER` / `KIND_CONTEXT` | `apf-e2e` / `kind-apf-e2e` | kind cluster and kubectl context |
| `OPENSHELL_NS` / `APF_NS` | `openshell` / `apf` | namespaces |
| `OPENSHELL_RELEASE` / `APF_RELEASE` | `openshell` / `apf` | Helm release names |
| `APF_FULLNAME` | `apf` | `fullnameOverride` and Service name of the APF release |
| `OPENSHELL_CHART` / `OPENSHELL_VERSION` | `oci://ghcr.io/nvidia/openshell/helm-chart` / `0.1.3` | OpenShell chart |
| `OPENSHELL_IMAGE_TAG` | `0.1.3` | gateway, sandbox runtime, and supervisor image tag |
| `OPENSHELL_SERVICE_PORT` | `8080` | gateway Service port |
| `APF_IMAGE_TAG` | `dev` | tag of the local `apf-policy-service` and `apf-policy-gateway` images |
| `APF_ADMISSION_PORT` / `APF_EGRESS_PORT` | `18081` / `9099` | sandbox admission and egress request policy listener ports (chart defaults) |
| `SANDBOX_IMAGE` | `nvcr.io/nvidia/base/ubuntu:24.04` | default sandbox image |
| `PIP_STUB_IMAGE` | `python:3.12-slim` | image of the pip-stub sidecar |
| `PIP_STUB_PORT` / `PIP_STUB_HEALTH_PATH` | `19500` / `/healthz` | loopback port the stub listens on and the path that must answer 200 |
| `AGENT_SANDBOX_VERSION` | `v1.0.3` | agent-sandbox release |
| `E2E_WORK` | `deploy/helm/e2e/.work` | work directory |
| `BUNDLE_SRC` | `examples/demo-bundle` | bundle source directory with a `*.template.yaml` and its members |
| `BUNDLE_V2_TRANSFORM` | unset | executable that receives the staged revision-2 directory and edits members before signing |
| `PIP_CONFIG_SRC` | unset (lane off) | provider registration; `fixtures/pip/pips.yaml` turns the lane on with the in-repo stub |
| `PIP_STUB_SRC` | `fixtures/pip/stub.py` | script the pip-stub sidecar runs (`python3 /app/stub.py --port <PIP_STUB_PORT>`) |
| `OPENSHELL_CLI` | `E2E_WORK/openshell` if present, else `openshell` on `PATH` | OpenShell CLI 0.1.3 used by `smoke.sh` |
| `OPENSHELL_LOCAL_PORT` | `18080` | local port for the gateway port-forward |
| `APF_COMPILE` | `target/release/apf-compile` | bundle signing tool |
| `DEV_KEYS_DIR` / `SIGNING_KEY_ID` | `examples/dev-keys` / `apf-dev` | development signing seed and trust key |
| `KEEP_SANDBOX` | unset | `1` keeps the test sandbox after `smoke.sh` |
| `E2E_MATERIALS_LOCAL_ONLY` | unset | `1` makes `materials.sh` stop after the steps that need no cluster |

## Notes

- `apf-values-pip.yaml` sets `policyGateway.pip.configMap: apf-pip`; the chart
  mounts the registration file and passes `--pip-config` itself.

## Optional: policy information provider lane

Off by default. Turning it on proves at runtime that the chart's
`policyGateway.pip.*` values start the gateway with `--pip-config` and that
`extraContainers` carries a loopback provider:

```sh
PIP_CONFIG_SRC=deploy/helm/e2e/fixtures/pip/pips.yaml deploy/helm/e2e/up.sh --skip-cluster
```

`materials.sh` then publishes the registration (`apf-pip`) and the stub script
(`apf-pip-stub`) as ConfigMaps, `up.sh` layers `apf-values-pip.yaml` on the
chart install, and `smoke.sh` adds the sidecar check. The gateway accepts
plain-`http` provider URLs on loopback only, so the stub runs as a sidecar in
the APF pod at `http://127.0.0.1:19500`; a provider outside the pod must be
served over HTTPS, with `endpoint.tls` in the registration carrying a private
CA and client certificate when needed.

## Composing a demo on top

The harness carries no demo content. A demo points the knobs above at its own
material and reuses the scripts unchanged:

```sh
APF_DIR=/path/to/apf
BUNDLE_SRC=/path/to/demo/bundle \
BUNDLE_V2_TRANSFORM=/path/to/demo/bundle-v2.sh \
PIP_CONFIG_SRC=/path/to/demo/pips.yaml \
PIP_STUB_SRC=/path/to/demo/provider-mock.py \
PIP_STUB_HEALTH_PATH=/demo/state \
  "$APF_DIR/deploy/helm/e2e/up.sh"
```

The stub script must accept `--port`, bind `127.0.0.1`, and answer
`PIP_STUB_HEALTH_PATH` with 200; the registration must use
`http://127.0.0.1:<PIP_STUB_PORT>` URLs.
- Offline `helm template` of the OpenShell chart needs
  `--api-versions agents.x-k8s.io/v1beta1` or
  `--set agentSandbox.preflight.enabled=false`; the real install finds the CRD
  installed by `kind.sh`.
- The development signing key and trust root under `examples/dev-keys` are for
  this harness only.
