<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Verification harness

One suite, run unchanged against every way APF is deployed. An environment
wrapper brings a stack up, exports a small contract describing it, runs a
command with that environment and tears the stack down; a suite reads the
contract and talks to the stack through a handful of dispatch functions.
There are two environments:

| Wrapper | Stack |
| --- | --- |
| `e2e/with-compose-stack.sh` | the Docker Compose stack of `deploy/docker/compose.yaml`, APF alone or with an OpenShell gateway overlay |
| `e2e/with-kind-stack.sh` | the Helm chart `deploy/helm/apf` on a local kind cluster next to an OpenShell gateway installed from its own chart |

OpenShell and the sandbox image are fixtures of this harness, not
deliverables: the compose file and the chart stay APF-only, and the files
under `e2e/configs/` register OpenShell against APF only to exercise it. The
harness carries no demo content; a demo composes it through knobs.

```text
e2e/
├── with-compose-stack.sh      # compose lifecycle wrapper
├── with-kind-stack.sh         # kind lifecycle wrapper
├── support/
│   ├── common.sh              # shared helpers and fixture knobs
│   ├── env.sh                 # what a suite sources: the contract and the environment's dispatch functions
│   ├── env-compose.sh         # compose knobs and dispatch functions
│   ├── env-kind.sh            # kind knobs and dispatch functions
│   ├── compose-stack.sh       # compose lifecycle (preflight, materials, up, ready, down)
│   ├── kind-stack.sh          # kind lifecycle (OpenShell, materials, APF, registration, port-forwards, down)
│   ├── kind-cluster.sh        # kind cluster, agent-sandbox, image preload
│   ├── materials.sh           # bundle signing, certificates, trust profiles, tokens
│   └── openshell.sh           # OpenShell CLI lookup and download, proto pin, trust profiles, `cli`
├── configs/
│   ├── compose/               # OpenShell and provider overlays for compose.yaml
│   ├── gateway/               # OpenShell gateway TOML, one per compute driver
│   ├── kind/                  # OpenShell and APF values for kind, the evaluate debug profile
│   └── pip/                   # provider registration fixture and the loopback stub
├── suites/
│   ├── smoke.sh               # the stack serves decisions; OpenShell admits a sandbox through APF
│   └── parity.sh              # static: compose and chart start the binaries with the same flags
└── .work/                     # gitignored: OpenShell CLI, per-environment materials and logs
```

## Prerequisites

Done once, offline, on the workstation. Commands are relative to the
repository root.

1. Install the tools. Both environments: Docker Desktop or Docker Engine
   with Compose v2, `openssl`, `python3`, `tar`, `shasum`, `curl`. Compose
   also needs `lsof`; kind also needs `kind`, `kubectl`, `helm` 3 and `yq` v4
   (`brew install kind kubectl helm yq`). The parity suite needs `docker`,
   `helm` and `yq`.
2. Build the two APF images from the repository Dockerfiles. The harness
   never pulls them: compose runs them as they are, kind loads them into the
   cluster and installs with `pullPolicy: Never`.

   ```sh
   docker build -f deploy/docker/apf-policy-service/Dockerfile --target runtime -t apf-policy-service:dev .
   docker build -f deploy/docker/apf-policy-gateway/Dockerfile -t apf-policy-gateway:dev .
   ```

3. Build the bundle signing tool: `cargo build --release -p apf-compile`. The
   wrappers run this for you when `target/release/apf-compile` is missing.
4. Get the OpenShell CLI that matches the OpenShell under test (0.1.3). From
   the OpenShell GitHub release download `openshell-<triple>.tar.gz` for your
   host (`aarch64-apple-darwin`, `x86_64-unknown-linux-musl`,
   `aarch64-unknown-linux-musl`) together with
   `openshell-checksums-sha256.txt`, check the archive against it, and unpack
   the `openshell` binary to `e2e/.work/openshell`; shown for an Apple
   silicon host:

   ```sh
   curl -fsSLO https://github.com/NVIDIA/OpenShell/releases/download/v0.1.3/openshell-aarch64-apple-darwin.tar.gz
   curl -fsSLO https://github.com/NVIDIA/OpenShell/releases/download/v0.1.3/openshell-checksums-sha256.txt
   grep ' openshell-aarch64-apple-darwin.tar.gz$' openshell-checksums-sha256.txt | shasum -a 256 -c -
   mkdir -p e2e/.work && tar -xzf openshell-aarch64-apple-darwin.tar.gz -C e2e/.work openshell
   rm openshell-aarch64-apple-darwin.tar.gz openshell-checksums-sha256.txt
   ```

   `OPENSHELL_CLI=/path/to/openshell` names another binary. When the
   workstation is online the wrappers do this step themselves: a CLI of
   another version (the `openshell` on `PATH`, say) is replaced by a verified
   download into `e2e/.work/openshell`.
5. Make sure the workstation can reach `ghcr.io` (OpenShell images and chart,
   the sandbox image), `registry.k8s.io` (pause image), Docker Hub (`grpcurl`
   and the `python` image of the provider stub) and `github.com`
   (agent-sandbox manifest, OpenShell CLI).

## Quick start

Compose:

```sh
e2e/with-compose-stack.sh e2e/suites/smoke.sh                   # APF alone: checks 1-3
e2e/with-compose-stack.sh --openshell e2e/suites/smoke.sh       # with an OpenShell gateway: checks 1-7
e2e/with-compose-stack.sh --openshell --pip e2e/suites/smoke.sh # plus the provider lane: checks 1-8
```

Kind (an OpenShell gateway is always part of the run; the chart's trust
profiles are built from its extension-JWT key):

```sh
e2e/with-kind-stack.sh e2e/suites/smoke.sh                      # checks 1-7
e2e/with-kind-stack.sh --pip e2e/suites/smoke.sh                # checks 1-8
```

Static, no stack:

```sh
e2e/suites/parity.sh
```

The same runs as mise tasks: `mise run e2e:compose`, `e2e:compose:openshell`,
`e2e:kind`, `e2e:parity`. `mise run dev` builds the images and brings the
compose stack up standalone with the smoke suite, keeping it running;
`dev-logs` follows its logs and `dev-down` removes it.

A run is hermetic: the wrapper tears the stack down afterwards, compose
volumes included, so the anti-rollback counter never blocks a later run with
a different bundle. To keep a stack and work against it:

```sh
e2e/with-compose-stack.sh --openshell --keep e2e/suites/smoke.sh   # run, then keep
e2e/with-compose-stack.sh --openshell                              # or: bring up, keep, print the contract
e2e/with-compose-stack.sh --existing e2e/suites/smoke.sh           # run against the kept stack
e2e/with-compose-stack.sh --logs policy-gateway                    # follow a component's log
e2e/with-compose-stack.sh --down --volumes                         # remove it; without --volumes the volumes stay
e2e/with-compose-stack.sh --prepare --openshell                    # materials and volumes only; nothing started
```

`e2e/with-kind-stack.sh` takes the same `--keep`, `--existing`, `--logs`
and `--down` (`--down --cluster` also deletes the kind cluster). The knobs a
run was rendered with (ports, gateway id, image tags, lanes) are recorded in
`e2e/.work/<environment>/run.env`; `--existing`, `--logs` and `--down` read
them, so a stack brought up with `OPENSHELL_PORT=28080` is addressed on that
port later without repeating the knob. A value set in the environment still
wins over the recorded one.

On a workstation where something else holds the published ports (8080, 8081,
9099 by default), export `OPENSHELL_PORT`, `OPENSHELL_HEALTH_PORT` and
`APF_EGRESS_PORT` for the compose run; preflight names the holder of a busy
port.

## The contract

A wrapper exports these before it runs a command; a suite reads only them.

| Variable | compose | kind |
| --- | --- | --- |
| `APF_E2E_ENV` | `compose` | `kind` |
| `APF_E2E_OPENSHELL` | `1` with `--openshell`, else `0` | always `1` |
| `APF_E2E_PIP` | `0` / `1` | `0` / `1` |
| `APF_E2E_WORK` | `e2e/.work/compose` | `e2e/.work/kind` |
| `APF_E2E_LOG_DIR` | `${APF_E2E_WORK}/logs` | same |
| `APF_E2E_GATEWAY_URL` | `http://127.0.0.1:${OPENSHELL_PORT}`; empty without OpenShell | `http://127.0.0.1:<port>` through a `kubectl port-forward` to the gateway Service |
| `APF_E2E_HEALTH_URL` | `http://127.0.0.1:${OPENSHELL_HEALTH_PORT}` | `http://127.0.0.1:<port>` through a port-forward to the pod's health port |
| `APF_E2E_OPENSHELL_CLI` | the resolved CLI path | same |
| `APF_E2E_OPENSHELL_VERSION` | `OPENSHELL_IMAGE_TAG` | `OPENSHELL_VERSION` |
| `APF_E2E_BUNDLE_DIGEST` | file holding the sha256 of the signed document | same |
| `APF_E2E_PIP_STUB_URL` | `http://127.0.0.1:${PIP_STUB_PORT}${PIP_STUB_HEALTH_PATH}`; empty without the lane | same |
| `APF_E2E_SANDBOX_NAME` | `apf-e2e` | same |
| `APF_E2E_KEEP_SANDBOX` | `0` / `1` | same |
| `APF_E2E_APF_DIR` | repository root | same |

The stack is reached through dispatch functions whose implementation
`e2e/support/env.sh` selects by `APF_E2E_ENV`; suites never call `docker`,
`kubectl` or `helm` themselves. Components are `policy-service`,
`policy-gateway`, `openshell-gateway` and `pip-stub`.

| Function | Meaning |
| --- | --- |
| `apf_e2e_components` | the components of this run, from `APF_E2E_OPENSHELL` and `APF_E2E_PIP` |
| `apf_e2e_ready <component>` | 0 when the component is running and ready (compose: running and healthy; kind: the container reports ready) |
| `apf_e2e_logs <component>` | the current log on stdout, ANSI colour codes stripped |
| `apf_e2e_exec <component> <command...>` | run a command in the component |
| `apf_e2e_audit_tail <component> <file> <n>` | the last `n` lines of `/var/log/apf/audit/<file>` |
| `apf_e2e_evaluate <request.json>` | an `EvaluateRequest` over the gateway socket: 0 with the response on stdout, 1 failed (reason on stderr), 2 unsupported in this environment (reason on stderr) |
| `apf_e2e_dump_state` | the stack's state on stderr, used by failing lifecycle steps |
| `cli <args...>` | the OpenShell CLI against `APF_E2E_GATEWAY_URL` with `--gateway-insecure` |

Compose sends the evaluate request from the pinned `grpcurl` image, run as
65532 with the socket volume and `contracts/proto` attached. Kind adds an
ephemeral `grpcurl` container to the APF pod (`kubectl debug` with the
profile `configs/kind/evaluate-debug-profile.yaml`: user 65532, the gateway
socket volume and a ConfigMap holding the two proto files) and reads the
response from its log once it terminated. The function returns 2, and the
suite prints `skip` with the reason, when the pod lacks the `evaluate-proto`
volume (a release installed without the values the wrapper renders) or when
the API refuses the ephemeral container or the custom profile; an image that
never starts or a non-zero `grpcurl` exit is a failure, reported with the
container's waiting reason or its output.

### Writing a suite

```sh
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/support/env.sh"

apf_e2e_ready policy-gateway || fail "policy-gateway is not ready"
apf_e2e_logs policy-service | grep -q 'bundle verified and loaded'
if [[ "${APF_E2E_OPENSHELL}" == 1 ]]; then cli gateway info; else skip "no OpenShell in this run"; fi
```

A check prints `ok`, `FAIL` or `skip` with the reason; a suite exits 1 when
any check failed, and skips never fail. Artifacts go to `APF_E2E_LOG_DIR`.
A new environment is a new `support/env-<name>.sh` defining the same
functions; nothing in `env.sh` or the suites changes for it.

## What a wrapper does

Each step writes `e2e/.work/<environment>/logs/<step>.log` and, when it
fails, appends the stack's state; the wrapper then tears down (unless
`--keep`) and exits 1.

Compose (`with-compose-stack.sh`):

0. **preflight**: engine reachable, Compose v2, `latest` refused for the two
   image tags, both APF images present (`--build` builds them first), the
   signing seed, trust root and bundle source exist; with `--openshell` also
   the OpenShell CLI of the version under test, the engine socket, `lsof`
   and `curl`, and the published ports free or held by this project's own
   pod from an earlier run.
1. **materials**: both bundle revisions signed and verified offline, the
   provider registration staged (`--pip`), and with `--openshell` the serving
   certificate (SANs `localhost`, `host.openshell.internal`, `127.0.0.1`), the
   extension-JWT key pair, the two trust profiles and the rendered gateway
   TOML. Then `docker compose up --no-start` creates the project and its
   volumes, a root throwaway run of the policy-service image hands the APF
   volumes to user 65532, and further throwaway runs write the secrets and
   the listener material into them as 65532 and the extension-JWT key pair
   into `openshell-jwt` as root, with owner-only modes; each party mounts
   only its own volume. The throwaway containers run without network, with a
   read-only root filesystem and no capabilities beyond the ones a step
   needs (`CHOWN`, `FOWNER`, `DAC_OVERRIDE` for the ownership step).
2. **up**: `docker compose up -d` for `pod`, `policy-service` and
   `policy-gateway` (and `pip-stub`); when the signed document changed since
   the previous run the two APF containers are recreated, since the service
   reads the bundle at startup; with `--openshell` the OpenShell gateway is
   recreated once the policy gateway is healthy, because it reads its TOML
   at startup and the TOML is rendered on every run.
3. **ready**: every container running and healthy; the OpenShell gateway
   answers `/readyz`, which it does only after `Describe` succeeded on every
   registered extension.

Teardown deletes the sandboxes the OpenShell gateway still holds through the
CLI while the gateway runs, which works the same on every compute driver,
then stops the gateway. With the Docker driver it also removes the sandbox
containers and volumes labelled with this run's namespace
(`OPENSHELL_GATEWAY_ID`, which the rendered TOML sets as `sandbox_label`);
the Podman driver labels sandboxes with the request namespace that other
gateways on the engine share, so there is no label sweep for it. Then
`docker compose down --remove-orphans`, with `--volumes` in run mode and for
`--down --volumes`, which also empties the OpenShell state directory through
a root throwaway run when that directory lies under `e2e/.work`; a state
directory elsewhere is left in place. The `openshell-docker` network carries
no namespace label and is shared with other gateways on the engine, so it
stays.

Kind (`with-kind-stack.sh`):

0. **preflight**: `kind`, `kubectl`, `helm`, `yq` and the engine, `latest`
   refused, the APF images present locally, the inputs, the OpenShell CLI.
1. **cluster**: the kind cluster (created when missing), agent-sandbox, and
   the images in the node: the APF images are reloaded on every run; the
   OpenShell gateway, sandbox and supervisor images, the sandbox image, the
   `grpcurl` image and the provider stub image are pulled when missing and
   skipped when the node already has them. A digest reference cannot be
   loaded into kind as such, so it is tagged `<repository>:apf-e2e-<12 hex>`
   and that tag is loaded; the rendered values use the tag. The first run on
   a cluster loads the sandbox image (2.8 GB) into the node, which takes a
   few minutes; later runs find it there.
2. **openshell**: the values rendered from the environment, then OpenShell
   installed without extensions; its certgen Job writes Secret
   `<release>-jwt-keys`. A release left pending by an interrupted run is
   recovered first (a pending install is uninstalled, a pending upgrade rolled
   back to the last deployed revision).
3. **materials**: both bundle revisions, the serving certificate with the APF
   Service DNS names, the trust profiles from the JWT Secret, and Secrets
   `apf-runtime` and `apf-egress`, ConfigMaps `apf-trust`, `apf-bundle` and
   `apf-evaluate-proto` in the APF namespace and `apf-ca` in the OpenShell
   namespace; with `--pip` also `apf-pip` and `apf-pip-stub`.
4. **apf**: `helm lint --strict`, then `helm upgrade --install` of the chart
   with `configs/kind/apf-values.yaml` (and `apf-values-pip.yaml`). The
   signed document's digest goes on the pod as an annotation, so the pod
   rolls exactly when the bundle changes.
5. **register**: OpenShell upgraded with `configs/kind/openshell-values-apf.yaml`,
   which adds the sandbox admission, egress request policy and
   provider-profile-source stanzas under OpenShell's own keys and mounts the
   APF certificate from ConfigMap `apf-ca`. The gateway TOML OpenShell rendered
   is saved to `logs/openshell-gateway.toml`.
6. **port-forwards** to the gateway Service and to the pod's health port
   (the Service exposes only gRPC and metrics); kubectl picks the local ports
   and the wrapper reads them back. They live as long as the wrapper, so
   `--existing` starts new ones. Their pids are recorded in
   `port-forward.pids`; a run, and `--down`, first end what an interrupted
   one left behind. With `OPENSHELL_LOCAL_PORT` pinned, a run also ends a
   stale `kubectl port-forward` holding that port, while any other holder is
   reported with the knob.

Teardown uninstalls both releases and deletes their namespaces (deleting the
Sandbox objects first so finalizers cannot stall it); the cluster and its
preloaded images stay unless `--down --cluster`. The state PVC goes with the
APF namespace, so every run starts with a fresh anti-rollback counter. A
kept stack keeps it: when the signed document changes at the same revision
(an edited bundle source, say), the policy service refuses the new document
with `counter_content_mismatch`, and the stack must be taken down first;
the wrapper says so when it sees the change on an installed release.

### Install order and trust

The OpenShell gateway calls `Describe` on every registered extension at
startup and fails closed when one is unreachable, and APF needs OpenShell's
extension-JWT public key before it can verify callers. Both constraints fix
the order: OpenShell first without extensions, APF second once the trust
profiles exist, OpenShell again with the registration. Compose has the same
shape with the gateway's own key pair generated by the harness: the policy
gateway is healthy before the OpenShell gateway starts
(`depends_on: service_healthy`), and the TOML's `gateway_jwt` table points
at the generated key in the `openshell-jwt` volume.

Trust is symmetric. APF trusts OpenShell's JWT key with issuer
`openshell-gateway:<gateway id>` and one audience per listener, named by
OpenShell's extension type (`urn:openshell:extension:interceptor:<id>` for
sandbox admission, `urn:openshell:extension:middleware:<id>` for egress
request policy); OpenShell trusts the APF serving certificate. Each side
holds only its own private key in both environments: on kind the APF keys
are in Secrets `apf-runtime` and `apf-egress` and OpenShell keeps its JWT key
in its own Secret, on compose the APF keys are in `apf-openshell`, mounted by
the policy gateway alone, and the JWT key pair in `openshell-jwt`, mounted by
the OpenShell gateway alone; the public halves travel as `ca.crt` and the
trust profiles.

### Materials, one library, two deliveries

`support/materials.sh` builds everything and touches no engine or cluster;
the environment lifecycle delivers it.

| Material | compose | kind |
| --- | --- | --- |
| Signed bundle v1 and v2 | staged under `e2e/.work/compose`; v1 bind-mounted read-only | `bundle-v1.tar.gz` in ConfigMap `apf-bundle`; the chart's init container untars it |
| Trust root `apf-dev.pub` | bind mount from `DEV_KEYS_DIR` | ConfigMap `apf-trust` |
| Signing seed, HTTP token | volume `apf-secrets`, `0400`, owned by 65532 | Secret `apf-runtime` |
| Serving certificate | volume `apf-openshell` (`interceptor/`, `middleware/`, `ca.crt`; policy gateway only) and `ca.crt` in volume `openshell-jwt` (OpenShell gateway only) | Secrets `apf-runtime` (interceptor) and `apf-egress` (middleware), ConfigMap `apf-ca` |
| OpenShell extension-JWT key | generated into volume `openshell-jwt` (`jwt/{signing.pem,public.pem,kid}`, root-owned, OpenShell gateway only), named by the TOML's `gateway_jwt` table | read from Secret `<release>-jwt-keys` written by OpenShell |
| Trust profiles | `apf-openshell/<listener>/trust.toml` | `trust.toml` in the two Secrets |
| APF registration | rendered copy of `configs/gateway/openshell-gateway.<driver>.toml` | `configs/kind/openshell-values-apf.yaml` applied with `helm upgrade` |
| Provider registration and stub | bind mounts of `configs/compose/compose.pip.yaml` | ConfigMaps `apf-pip`, `apf-pip-stub`; sidecar from `apf-values-pip.yaml` |
| Evaluate protos | `contracts/proto` bind-mounted into the `grpcurl` run | ConfigMap `apf-evaluate-proto` mounted into the ephemeral container |

## Suites

### `suites/smoke.sh`

1. Every component of the run is running and ready.
2. The policy service logged `bundle verified and loaded` with the digest of
   the exact document the wrapper signed (`APF_E2E_BUNDLE_DIGEST`).
3. `examples/evaluate/deny.json` is denied and `allow.json` allowed over the
   gateway socket, and the last line of `apf-policy-gateway-audit.jsonl`
   carries the response's policy digest. `skip` where the environment cannot
   reach the socket.
4. The OpenShell gateway answers `/readyz` and logged
   `gateway interceptors initialized bindings=14 profile_sources=1`.
5. `openshell gateway info` through `APF_E2E_GATEWAY_URL`.
6. Sandbox admission: `openshell sandbox create --name apf-e2e --detach --
   sleep 3600` succeeds and the sandbox carries the `apf.nvidia.com/bundle-id`
   and `apf.nvidia.com/provenance-token` annotations (printed).
7. Sandbox admission: the gateway log records
   `gateway interceptor evaluated … interceptor=apf/policy-adapter … decision="allow"`
   and `apf-policy-gateway-interceptor-audit.jsonl` an
   `interceptor.policy_injected` event.
8. The provider stub is ready and `GET` of `APF_E2E_PIP_STUB_URL` from inside
   the pod returns 200.

Checks 4–7 print `skip` when `APF_E2E_OPENSHELL=0`, check 8 when
`APF_E2E_PIP=0`. Artifacts (`evaluate-*.json`, `gateway-info.txt`,
`sandbox-*.json`, `openshell-gateway.log`, `*-audit.tail.jsonl`) land in
`APF_E2E_LOG_DIR`. The sandbox is deleted at the end unless
`APF_E2E_KEEP_SANDBOX=1`. Egress request policy is registered but not
exercised: the test sandbox makes no outbound request.

### `suites/parity.sh`

Renders `deploy/docker/compose.yaml` (with the overlays) through
`docker compose config` and the chart through `helm template`, and compares
the flags each binary starts with, per lane: `standalone` (compose alone
against the chart's listener-less shape), `openshell` and `openshell+pip`.
Flags whose value is a path or an environment-specific address compare by
name; the rest by value. One side may carry a flag alone only when the suite
lists it with a reason: `--document-ttl-secs` (the kind values set it),
`--pip-stage-budget-ms` (values-driven), and in the standalone lane the two
sandbox admission flags, because the chart always serves that listener. An
`APF_*` environment entry compose sets must be in the suite's
environment-to-flag table. The suite prints one table per lane and binary
and exits 1 on any other difference.

## Work directory and logs

Everything generated lands under `E2E_WORK` (default `e2e/.work`,
gitignored): `openshell` (the CLI) and one directory per environment.

- `compose/`: `run.env`; `bundle-v1/`, `bundle-v2/`, the tarballs and
  `bundle-*.digest`; `http-bearer-token`; `tls/apf.{crt,key}`;
  `openshell-jwt/{signing.pem,public.pem,kid}`; `trust-interceptor.toml`,
  `trust-middleware.toml`; `openshell-gateway.toml` (the rendered TOML the
  overlay mounts); `openshell-state/` (the gateway's database and driver
  state); `pips.yaml`; `logs/`.
- `kind/`: `run.env`, `node-images.env`, `port-forward.pids` (while the
  wrapper runs); the bundles, token and `tls/` as above;
  `openshell-jwt-public.pem`, `openshell-jwt-kid`, the two trust profiles;
  `pips.yaml`; `values/` (the rendered copies of `configs/kind/*.yaml`);
  `logs/`, including `openshell-gateway.toml` and the `port-forward-*.log`
  files.

`logs/<step>.log` holds every lifecycle step's output with the state dump
appended on failure; the suites write their artifacts next to them. No
wrapper action removes the work directory.

## Knobs

Every value can be set in the environment. Shared:

| Variable | Default | Meaning |
| --- | --- | --- |
| `APF_IMAGE_TAG` | `dev` | tag of the local `apf-policy-service` and `apf-policy-gateway` images (`latest` refused) |
| `OPENSHELL_IMAGE_TAG` | `0.1.3` | OpenShell gateway, supervisor and sandbox runtime image tag (`latest` refused) |
| `OPENSHELL_VERSION` | `OPENSHELL_IMAGE_TAG` | OpenShell chart version (kind) and the CLI version the wrappers require |
| `OPENSHELL_IMAGE_REGISTRY` | `ghcr.io/nvidia/openshell` | registry of the OpenShell images |
| `OPENSHELL_CLI` | `e2e/.work/openshell`, else `openshell` on `PATH` | the OpenShell CLI; a version other than `OPENSHELL_VERSION` is replaced by a verified download unless set explicitly |
| `SANDBOX_IMAGE` | `ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:e29a8e98…` | default image for `openshell sandbox create`; must define the `sandbox` user the demo policy names |
| `GRPCURL_IMAGE` | `fullstorydev/grpcurl@sha256:085e183c…` (v1.9.3) | sends the evaluate requests |
| `APF_ADMISSION_PORT` / `APF_EGRESS_PORT` | `18081` / `9099` | sandbox admission and egress request policy listener ports |
| `APF_KEY_ID` / `SIGNING_KEY_ID` | `apf-dev` | document key id and trust-root file stem / bundle signing key id |
| `DEV_KEYS_DIR` | `examples/dev-keys` | development signing seed and trust key |
| `APF_COMPILE` | `target/release/apf-compile` | bundle signing tool |
| `BUNDLE_SRC` | `examples/demo-bundle` | bundle source directory with a `*.template.yaml` and its members |
| `BUNDLE_V2_TRANSFORM` | unset | executable that receives the staged revision-2 directory and edits members before signing |
| `PIP_CONFIG_SRC` | unset (`--pip`: `configs/pip/pips.yaml`) | provider registration; setting it turns the lane on |
| `PIP_STUB_SRC` / `PIP_STUB_IMAGE` | `configs/pip/stub.py` / `python@sha256:a6e34c59…` (3.12-slim) | script and image of the provider stub |
| `PIP_STUB_PORT` / `PIP_STUB_HEALTH_PATH` | `19500` / `/healthz` | loopback port the stub listens on and the path that must answer 200 |
| `E2E_WORK` | `e2e/.work` | work root |
| `APF_E2E_SANDBOX_NAME` | `apf-e2e` | the sandbox the smoke suite creates |
| `APF_E2E_KEEP_SANDBOX` | `0` | `1` keeps that sandbox (`KEEP_SANDBOX` is an alias) |

Compose:

| Variable | Default | Meaning |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `apf` | compose project; volumes are `<project>_<volume>` |
| `OPENSHELL_GATEWAY_ID` | `<project>-compose` | `gateway_jwt.gateway_id`, the issuer suffix, the audiences and, with the Docker driver, the namespace label the gateway stamps on its sandbox containers |
| `OPENSHELL_COMPUTE_DRIVER` | `docker` | `docker` or `podman`: the TOML variant and the engine driving sandboxes |
| `CONTAINER_SOCKET` | `/var/run/docker.sock` | engine API socket mounted into the OpenShell gateway, as the engine resolves the bind source: inside a Podman machine it is the machine's path, not the host socket in `DOCKER_HOST` |
| `OPENSHELL_PORT` / `OPENSHELL_HEALTH_PORT` | `8080` / `8081` | gateway gRPC and health, published on `127.0.0.1` |
| `OPENSHELL_STATE_DIR` | `e2e/.work/compose/openshell-state` | gateway state, bind-mounted at the same path inside the container; required by the overlay, and emptied by the teardown only when it lies under `e2e/.work` |
| `OPENSHELL_GATEWAY_TOML` | `e2e/.work/compose/openshell-gateway.toml` | the rendered gateway TOML the overlay mounts |
| `APF_BUNDLE_DIR` / `APF_TRUST_ROOT` | `e2e/.work/compose/bundle-v1/bundle` / `examples/dev-keys/apf-dev.pub` | what `compose.yaml` bind-mounts |
| `PIP_CONFIG` | `e2e/.work/compose/pips.yaml` | the copy of the provider registration the provider overlay mounts |

Kind:

| Variable | Default | Meaning |
| --- | --- | --- |
| `KIND_CLUSTER` | `apf-e2e` | kind cluster; the kubectl context is the one kind creates for it, `kind-<cluster>`, and is not a knob because the teardown is destructive on it |
| `OPENSHELL_NS` / `APF_NS` | `openshell` / `apf` | namespaces |
| `OPENSHELL_RELEASE` / `APF_RELEASE` | `openshell` / `apf` | Helm release names |
| `APF_FULLNAME` | `apf` | `fullnameOverride` and Service name of the APF release |
| `OPENSHELL_CHART` | `oci://ghcr.io/nvidia/openshell/helm-chart` | OpenShell chart |
| `OPENSHELL_SERVICE` | `OPENSHELL_RELEASE` | gateway Service the port-forward targets |
| `OPENSHELL_SERVICE_PORT` | `8080` | gateway Service port |
| `OPENSHELL_LOCAL_PORT` | `0` (kubectl picks) | local port of the gateway port-forward; a stale `kubectl port-forward` holding a pinned port is ended first |
| `OPENSHELL_JWT_SECRET` | `<release>-jwt-keys` | Secret the extension-JWT public key and kid are read from for the trust profiles |
| `OPENSHELL_GATEWAY_ID` | `OPENSHELL_RELEASE` | issuer suffix and audiences |
| `AGENT_SANDBOX_VERSION` | `v1.0.3` | agent-sandbox release |

## Signing and verification

The wrappers sign the bundle the way a policy pipeline does and show the
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

   `keyid` must equal the file stem of the public key in the trust root
   (`apf-dev` ↔ `apf-dev.pub`); that is how the policy service finds the key
   to verify with.
2. The wrapper then runs the same verification the policy service runs at
   startup, offline:

   ```sh
   target/release/apf-compile compile --verify-only \
     --bundle-path e2e/.work/compose/bundle-v1/bundle/manifest.yaml \
     --trust-root-dir examples/dev-keys --key-id apf-dev
   # verified  digest=<sha256 of manifest.yaml> counter=1
   ```

   and records the document's sha256 in `bundle-v1.digest`
   (`APF_E2E_BUNDLE_DIGEST`).
3. In the stack, the policy service logs
   `bundle verified and loaded path=/data/bundles/bundle/manifest.yaml digest=<sha256> counter=1`;
   smoke check 2 compares that digest with the recorded one, so the run
   proves the service verified exactly the document the harness signed. The
   sandbox then carries `apf.nvidia.com/signer-identity: apf-dev` and a
   provenance token minted by the policy service.

To see verification refuse a change made after signing, edit any member of a
staged bundle and verify again:

```sh
cp -R e2e/.work/compose/bundle-v1/bundle /tmp/tampered
printf '\n# edited after signing\n' >> /tmp/tampered/provider-profiles/github.yaml
target/release/apf-compile compile --verify-only --bundle-path /tmp/tampered/manifest.yaml \
  --trust-root-dir examples/dev-keys --key-id apf-dev
# Error: verification failed: ["manifest_hash_mismatch: provider-profiles/github.yaml: declared …, actual …"]
```

The policy service refuses such a bundle the same way at startup, and the
OpenShell gateway, registered fail-closed, then admits no sandbox.

Both revisions are staged on every run (`bundle-v2` is revision 1 with
`policy_revision: 2`, plus whatever `BUNDLE_V2_TRANSFORM` changes). To
re-sign one revision by hand, in a bash shell (the support files are bash
libraries):

```bash
source e2e/support/common.sh && source e2e/support/env-compose.sh && source e2e/support/materials.sh
stage_bundle v2        # into e2e/.work/compose/bundle-v2
```

The anti-rollback counter refuses a document whose revision was already
accepted with a different content; a run's teardown removes the counter with
the compose volumes or the kind namespaces, and for a kept stack
`with-compose-stack.sh --down --volumes` or `with-kind-stack.sh --down` does
the same.

## Composing a demo

The harness carries no demo content. A demo points the knobs at its own
material and reuses the wrappers and suites unchanged:

```sh
APF_DIR=/path/to/apf
BUNDLE_SRC=/path/to/demo/bundle \
BUNDLE_V2_TRANSFORM=/path/to/demo/bundle-v2.sh \
PIP_CONFIG_SRC=/path/to/demo/pips.yaml \
PIP_STUB_SRC=/path/to/demo/provider-mock.py \
PIP_STUB_HEALTH_PATH=/demo/state \
SANDBOX_IMAGE=/the/demo/sandbox/image \
  "$APF_DIR/e2e/with-compose-stack.sh" --openshell "$APF_DIR/e2e/suites/smoke.sh"
```

A non-empty `PIP_CONFIG_SRC` turns the provider lane on by itself. The stub
script must accept `--port`, bind `127.0.0.1`, and answer
`PIP_STUB_HEALTH_PATH` with 200; the registration must use
`http://127.0.0.1:<PIP_STUB_PORT>` URLs, because the gateway accepts plain
`http` providers on loopback only. A demo's own suite, wherever it lives,
sources `"${APF_E2E_APF_DIR}/e2e/support/env.sh"` and then uses the contract
like `suites/smoke.sh` does.

## Container engines

- **Docker Desktop (macOS)** is where the compose environment was verified,
  with the OpenShell Docker driver and the default sandbox image. The
  supervisor containers OpenShell starts run with host networking inside the
  Docker Desktop VM, and `grpc_endpoint = "http://127.0.0.1:<port>"` in the
  driver table makes the driver point their `host.openshell.internal` alias
  at loopback; the pod's `127.0.0.1` publishes are bound inside that VM too,
  so the supervisor reaches the gateway and the egress listener through them.
  The state bind must be under a directory Docker Desktop shares with the VM
  (`/Users`, `/tmp`, …), which the default under `e2e/.work` is.
- **Docker Engine (Linux)**: the same files. Keep `OPENSHELL_STATE_DIR` under
  `e2e/.work` (the default): the teardown empties only a state directory
  there, and a directory elsewhere may belong to another OpenShell gateway.
- **Podman**, through its Docker-compatible API socket, with
  `OPENSHELL_COMPUTE_DRIVER=podman` selecting
  `configs/gateway/openshell-gateway.podman.toml`, which pins
  `host_gateway_ip = "127.0.0.1"` because the Podman driver writes
  `host.openshell.internal` into the supervisor from that value, and Podman's
  default is not loopback. Two sockets are involved: `DOCKER_HOST` is the API
  socket the `docker` CLI and compose talk to, `CONTAINER_SOCKET` the path
  the engine resolves when it bind-mounts the API socket into the OpenShell
  gateway. Rootless on Linux they are the same file
  (`systemctl --user enable --now podman.socket`, then
  `DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock` and
  `CONTAINER_SOCKET=$XDG_RUNTIME_DIR/podman/podman.sock`). With a Podman
  machine they differ: `DOCKER_HOST` is the host-side socket
  `podman machine inspect` reports, `CONTAINER_SOCKET` the socket inside the
  machine, which preflight checks through `podman machine ssh`. The compose
  environment with the OpenShell overlay passes the smoke suite on a rootless
  Podman machine (Podman 6.1 client and server, `applehv` on Fedora CoreOS
  with SELinux enforcing, Compose v5.3.0, the `openshell` network on
  netavark with pasta):

  ```sh
  podman machine start
  HOST_SOCK="$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
  VM_UID="$(podman machine ssh -- id -u)"
  docker save apf-policy-service:dev apf-policy-gateway:dev | podman load
  podman pull ghcr.io/nvidia/openshell/gateway:0.1.3 ghcr.io/nvidia/openshell/supervisor:0.1.3 ghcr.io/nvidia/openshell/sandbox:0.1.3 \
    ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:e29a8e98c1399aa08a8c624d758d1814b6edbe0302eb570c0468a6d3e811d167
  DOCKER_HOST="unix://${HOST_SOCK}" OPENSHELL_COMPUTE_DRIVER=podman CONTAINER_SOCKET="/run/user/${VM_UID}/podman/podman.sock" \
    e2e/with-compose-stack.sh --openshell e2e/suites/smoke.sh
  podman machine stop
  ```

  The APF images are built by Docker, so they go into the machine's store
  through `podman load` (as `localhost/apf-policy-*:dev`, which the API
  resolves for the unqualified names in `compose.yaml`). The OpenShell images
  and the sandbox image are pulled into the same store ahead of the run, the
  sandbox image because 2.8 GB during the first `sandbox create` would
  outlast the CLI's wait; the pause and `grpcurl` images are pulled on demand
  through the API. Two engine differences surfaced on the way and are handled in the
  files: Podman's API accepts no `uid`/`gid` options on a tmpfs
  (`container create: unknown mount option "uid=65532": invalid mount option`),
  so the hardened `/tmp` in `compose.yaml` uses `mode=1777`; and with SELinux
  enforcing, label confinement denies the gateway container's connect to the
  bind-mounted API socket
  (`avc: denied { write } … name="podman.sock" scontext=…:container_t:… tcontext=…:user_tmp_t:… tclass=sock_file`),
  so the overlay runs that container with `security_opt: label=disable`.
  Everything else behaved as on Docker: the throwaway runs wrote the secrets
  into Podman volumes with the intended ownership and modes, the published
  ports reached the host through the machine, the Podman driver created the
  sandbox from the community base image, and APF admitted it. The Podman
  driver labels sandbox containers with the request namespace rather than
  the gateway id, so the teardown removes sandboxes on Podman only through
  the gateway: a sandbox left behind while the gateway is not running is
  removed with `openshell sandbox delete` (or `podman rm`) before `--down`.

## Notes

- Kind: terminated ephemeral containers from the evaluate check stay listed
  in the APF pod (`kubectl describe pod`) until its next restart; each call
  uses a new name (`apf-e2e-evaluate-<pid>-<random>-<n>`, `n` counting the
  pod's ephemeral containers) because ephemeral containers are immutable.
- Kind: `kind load docker-image` with a digest reference leaves the node
  without an image resolvable by it, hence the `apf-e2e-<12 hex>` tag.
- Kind: Helm replaces lists, so the rendered `apf-values-pip.yaml` carries
  the `evaluate-proto` volume as well as the stub script volume; the
  checked-in file lists only the latter.
- Kind: offline `helm template` of the OpenShell chart needs
  `--api-versions agents.x-k8s.io/v1beta1` or
  `--set agentSandbox.preflight.enabled=false`; the real install finds the CRD
  the cluster step installed.
- The OpenShell Docker driver resolves the `run_as_user` of the injected
  sandbox policy against the sandbox image and refuses an image without that
  user; the Kubernetes path does not perform this check. Both environments
  default to the community base image for that reason.
- The development signing key and trust root under `examples/dev-keys` are
  for this harness only. The OpenShell gateway runs plaintext with
  unauthenticated users and, in compose, as root with the engine socket: a
  verification fixture, not a deployment. For the same reason its compose
  container has `restart: on-failure`: a kept stack's OpenShell gateway does
  not come back after an engine restart or a reboot, while the APF containers
  (`unless-stopped`) do; `--down` and a new run bring everything back.
- The gateway TOMLs set no `app_armor_profile`, so the OpenShell driver emits
  no AppArmor option and the engine's default confinement applies to the
  sandbox containers on hosts that have it.
