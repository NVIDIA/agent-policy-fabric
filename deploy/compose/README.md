<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# APF compose stack

Brings APF up on a laptop from a clone with Docker Compose: the policy service
(verifies the signed bundle, serves projections, mints provenance documents)
and the policy gateway (the local decision point) as two hardened containers
sharing one network namespace. `compose.yaml` is APF only. OpenShell is how the
stack is verified, not part of it: `e2e/compose.openshell.yaml` adds a real
OpenShell gateway as an overlay, and the scripts under `e2e/` are the
executable form of that journey.

Topology: this stack runs the policy service and the policy gateway as two
containers in one network namespace sharing a Unix socket (the co-located
model), the same shape as the Helm chart. The target deployment separates
them: the policy service runs centrally and serves many gateways over the
network, and each policy gateway runs next to the OpenShell gateway it
governs, or centrally as well when latency and the features in use allow.
That split needs the networked policy-service transport, which does not exist
yet, so this stack does not offer it.

What the standalone stack is:

- `pod`: a pause container that owns the network namespace. The base file
  publishes no ports; the policy service binds loopback inside the namespace
  and the gateway serves a Unix socket.
- `policy-service`: `apf-policy-service serve` with the flags the chart passes
  for the local bundle source; HTTP on `127.0.0.1:19200` with a bearer token,
  the signed bundle and the trust root bind-mounted read-only, the anti-rollback
  counter on the `apf-state` volume, audit files on `apf-audit`.
- `policy-gateway`: `apf-policy-gateway` serving `EvaluationService/Evaluate`
  on `/run/apf/policy-gateway/policy-gateway.sock` (volume `apf-run`), fetching
  the policy set over the service socket and JWKS over loopback. Its two
  OpenShell listeners are off until the overlay enables them.
- Both run as `65532`, read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, a private `/tmp`.

## Quick start

The steps before `up.sh` are done once, offline, on the workstation. Commands
are relative to the repository root.

1. Install the tools: Docker Desktop or Docker Engine (or rootless Podman with
   its Docker-compatible socket) with Compose v2, `openssl`, `python3`, `tar`,
   `curl`, `lsof`. The signing tool needs a Rust toolchain (step 3).
2. Build the two APF images from the repository Dockerfiles. The stack never
   pulls them.

   ```sh
   docker build -f deploy/docker/apf-policy-service/Dockerfile --target runtime -t apf-policy-service:dev .
   docker build -f deploy/docker/apf-policy-gateway/Dockerfile -t apf-policy-gateway:dev .
   ```

3. Build the bundle signing tool: `cargo build --release -p apf-compile`.
   `e2e/materials.sh` runs this for you when `target/release/apf-compile` is
   missing.
4. For the OpenShell add-on, get the OpenShell CLI that matches the gateway
   under test (0.1.3): download `openshell-<arch>-<os>.tar.gz` from the
   OpenShell GitHub release, unpack it, and either put `openshell` on `PATH`,
   set `OPENSHELL_CLI=/path/to/openshell`, or drop the binary at
   `deploy/compose/e2e/.work/openshell`.
5. Make sure the workstation can reach `registry.k8s.io` (pause image), Docker
   Hub (`grpcurl`, and `python:3.12-slim` for the optional provider lane) and,
   for the add-on, `ghcr.io` (OpenShell gateway, supervisor, sandbox runtime
   and the default sandbox image).
6. Bring APF up alone and prove it:

   ```sh
   deploy/compose/e2e/up.sh
   ```

   This signs the bundle, writes the secrets into the volumes, starts
   `pod -> policy-service -> policy-gateway`, and runs smoke checks 1-3: both
   containers healthy, the policy service logged the digest of the exact
   document that was signed, and a decision came back over the gateway socket
   with a matching audit line.

7. Add OpenShell and admit a sandbox through APF:

   ```sh
   deploy/compose/e2e/up.sh --openshell
   ```

   The gateway TOML, the serving certificate, the extension-JWT key pair and
   the trust profiles are generated, the policy gateway is recreated with its
   OpenShell listeners on, and the OpenShell gateway starts once it is healthy.
   Smoke checks 4-7 then run: negotiation, `openshell gateway info`, a sandbox
   with `apf.nvidia.com/*` annotations, and the admission evidence in the
   gateway log and the APF audit file. `up.sh` prints the OpenShell version
   under test next to the OpenShell release APF's protos are pinned to; they
   may differ as long as the extension protocol major version matches, and
   the OpenShell gateway fails to start if it cannot negotiate with APF.

8. Look around, then tear down:

   ```sh
   cd deploy/compose
   docker compose -f compose.yaml -f e2e/compose.openshell.yaml ps
   docker compose -f compose.yaml -f e2e/compose.openshell.yaml logs policy-gateway
   e2e/down.sh            # stop and remove containers; volumes kept
   e2e/down.sh --volumes  # also reset the counter, secrets and OpenShell material
   ```

Other entry points:

```sh
deploy/compose/e2e/up.sh --build        # build the two images first (what `mise run dev` does)
deploy/compose/e2e/smoke.sh             # checks only, against a running stack
deploy/compose/e2e/materials.sh         # sign, write secrets into the volumes, nothing started
deploy/compose/e2e/materials.sh bundle v2   # re-sign revision 2 into e2e/.work
```

## The standalone journey, by hand

`up.sh` runs these steps; they are listed so the stack can be driven without
the harness. From `deploy/compose`, with `.env` copied from `.env.example`.
Bare `docker compose` commands read `.env`; the `e2e/*.sh` scripts take their
defaults from `e2e/env.sh` and ignore it, so the two files carry the same
values and a knob changed in one is changed in the other:

1. `e2e/materials.sh` signs `examples/demo-bundle` into
   `e2e/.work/bundle-v1/bundle` (what `compose.yaml` bind-mounts), runs
   `docker compose up --no-start` so compose creates the project's volumes,
   hands the fresh volumes to user 65532 through a root throwaway run of the
   policy-service image, and writes the bearer token and the document signing
   seed into `apf-secrets` through a second throwaway run as 65532
   (`docker run --rm -i --user 65532:65532 --entrypoint sh apf-policy-service:dev`),
   so both land as `0400` files owned by 65532 on every engine.
2. `docker compose up -d` starts the pod, then the policy service to healthy
   (`curl -fsS http://127.0.0.1:19200/readyz` inside the namespace), then the
   gateway to healthy (its socket exists).
3. Proofs, all from inside the namespace or over the socket volume because
   nothing is published:

   ```sh
   docker compose logs policy-service | grep 'bundle verified and loaded'
   docker compose exec policy-service sh -c 'curl -fsS -H "Authorization: Bearer $(cat /etc/apf/secrets/http-bearer-token)" http://127.0.0.1:19200/v1/documents/openshell.sandbox.v1'
   docker run --rm -i --user 65532:65532 -v apf_apf-run:/run/apf -v "$PWD/../../contracts/proto:/proto:ro" \
     fullstorydev/grpcurl@sha256:085e183ca334eb4e81ca81ee12cbb2b2737505d1d77f5e33dabc5d066593d998 \
     -plaintext -import-path /proto -proto nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto \
     -d @ unix:///run/apf/policy-gateway/policy-gateway.sock \
     nvidia.agent_policy_fabric.pdp.v1alpha1.EvaluationService/Evaluate < ../../examples/evaluate/deny.json
   docker compose exec policy-gateway tail -n 1 /var/log/apf/audit/apf-policy-gateway-audit.jsonl
   ```

   The grpcurl container attaches only the socket volume and the proto sources
   and runs as 65532, which the gateway's peer-credential check requires. The
   request files under `examples/evaluate/` give `DECISION_DENY` and
   `DECISION_ALLOW` against the demo bundle; the audit line carries the same
   `policy_digest`.

## The OpenShell journey

`up.sh --openshell` layers `e2e/compose.openshell.yaml` on the base file. The
overlay adds, without touching the base semantics:

- on `pod`: the alias `host.openshell.internal -> 127.0.0.1` and the publishes
  `127.0.0.1:8080` (gateway gRPC), `127.0.0.1:8081` (gateway health) and
  `127.0.0.1:9099` (egress request policy, for the host-network supervisor);
- on `policy-gateway`: the sandbox admission listener on `0.0.0.0:18081` and
  the egress request policy listener on `0.0.0.0:9099`, each with its TLS
  certificate and trust profile from the `apf-openshell` volume, plus
  `--openshell-gateway-url`; its healthcheck becomes a TCP connect to the
  egress listener, the signal the chart's readiness probe uses;
- `openshell-gateway`: OpenShell 0.1.3 in the pod namespace, started with
  `--config /etc/openshell/gateway.toml` (the rendered copy of
  `config/openshell-gateway.<driver>.toml`), the engine socket mounted at
  `/run/container-engine/engine.sock`, its state bind-mounted at the same path
  inside and outside the container, and `depends_on: policy-gateway: service_healthy`.

Order and trust are the same as in the Helm harness. The OpenShell gateway
calls `Describe` on every registered extension at startup and fails closed
when one is unreachable, so APF is healthy first. APF trusts OpenShell's
extension-JWT key (generated by `materials.sh`, `kid` in the TOML's
`gateway_jwt` paths) with issuer `openshell-gateway:apf-compose` and one
audience per listener, named by OpenShell's extension type
(`urn:openshell:extension:interceptor:apf-compose` for sandbox admission,
`urn:openshell:extension:middleware:apf-compose` for egress request policy);
OpenShell trusts the APF certificate, whose SANs are `localhost`,
`host.openshell.internal` and `127.0.0.1`.

With the stack up:

```sh
openshell --gateway-endpoint http://127.0.0.1:8080 --gateway-insecure gateway info
openshell --gateway-endpoint http://127.0.0.1:8080 --gateway-insecure sandbox create --name demo --detach -- sleep 3600
openshell --gateway-endpoint http://127.0.0.1:8080 --gateway-insecure sandbox get demo -o json | grep apf.nvidia.com/
docker compose -f compose.yaml -f e2e/compose.openshell.yaml logs openshell-gateway | grep 'gateway interceptor evaluated'
docker compose -f compose.yaml -f e2e/compose.openshell.yaml exec policy-gateway tail -n 5 /var/log/apf/audit/apf-policy-gateway-interceptor-audit.jsonl
```

Egress request policy is registered but not exercised: the test sandbox makes
no outbound request.

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

   `keyid` must equal the file stem of the public key in the trust-root
   directory (`apf-dev` ↔ `apf-dev.pub`); that is how the policy service finds
   the key to verify with.
2. The harness then runs the same verification the policy service runs at
   startup, offline:

   ```sh
   target/release/apf-compile compile --verify-only \
     --bundle-path deploy/compose/e2e/.work/bundle-v1/bundle/manifest.yaml \
     --trust-root-dir examples/dev-keys --key-id apf-dev
   # verified  digest=<sha256 of manifest.yaml> counter=1
   ```

   and records the document's sha256 in `e2e/.work/bundle-v1.digest`.
3. In the container, the policy service logs
   `bundle verified and loaded path=/data/bundles/bundle/manifest.yaml digest=<sha256> counter=1`;
   `smoke.sh` compares that digest with the recorded one, so the run proves the
   service verified exactly the document the harness signed. The sandbox then
   carries `apf.nvidia.com/signer-identity: apf-dev` and a provenance token
   minted by the policy service.

To see verification refuse a change made after signing, edit any member of a
staged bundle and verify again:

```sh
cp -R deploy/compose/e2e/.work/bundle-v1/bundle /tmp/tampered
printf '\n# edited after signing\n' >> /tmp/tampered/provider-profiles/github.yaml
target/release/apf-compile compile --verify-only --bundle-path /tmp/tampered/manifest.yaml \
  --trust-root-dir examples/dev-keys --key-id apf-dev
# Error: verification failed: ["manifest_hash_mismatch: provider-profiles/github.yaml: declared …, actual …"]
```

The policy service refuses such a bundle the same way at startup, and the
OpenShell gateway, registered fail-closed, then admits no sandbox.

## Smoke checks

`smoke.sh` prints `ok` or `FAIL` per check and exits non-zero if any failed:

1. Every container of the project is running and, where it has a healthcheck,
   healthy; `docker compose ps` is printed.
2. The policy service's `bundle verified and loaded` digest equals the sha256
   of the document `materials.sh` signed.
3. `examples/evaluate/deny.json` is denied and `allow.json` allowed over the
   gateway socket through the pinned `grpcurl` image, and the last line of
   `apf-policy-gateway-audit.jsonl` carries the response's policy digest.
4. With the overlay: the OpenShell gateway answers `/readyz` on its health
   port and logged `gateway interceptors initialized bindings=14 profile_sources=1`
   (it fails closed at startup when `Describe` on an extension fails).
5. `openshell gateway info` through the published port.
6. Sandbox admission: `openshell sandbox create --name apf-compose-e2e --detach --
   sleep 3600` succeeds and the sandbox carries the `apf.nvidia.com/bundle-id`
   and `apf.nvidia.com/provenance-token` annotations (printed).
7. Sandbox admission: the gateway log records a `gateway interceptor
   evaluated interceptor=apf/policy-adapter … decision="allow"` line and
   `apf-policy-gateway-interceptor-audit.jsonl` an `interceptor.policy_injected`
   event.
8. With PIP enabled: `GET http://127.0.0.1:19500/healthz` (`PIP_STUB_HEALTH_PATH`)
   from inside the pod returns 200.

The test sandbox is deleted at the end unless `KEEP_SANDBOX=1`.

## Files

| File | Role |
| --- | --- |
| `compose.yaml` | APF standalone: `pod`, `policy-service`, `policy-gateway`, the four named volumes |
| `.env.example` | Pinned tags, engine socket, driver, published ports, grpcurl image; copy to `.env` |
| `config/openshell-gateway.docker.toml`, `.podman.toml` | OpenShell gateway configuration with the APF registration, one per compute driver |
| `e2e/compose.openshell.yaml` | OpenShell overlay: publishes, listeners on the policy gateway, the OpenShell gateway |
| `e2e/compose.pip.yaml` | Provider lane: the `pip-stub` sidecar and `APF_PIP_CONFIG` on the policy gateway |
| `e2e/env.sh` | Shared variables, defaults, and helpers (`compose`, `volume_name`, `strip_ansi`, `dump_stack_state`) |
| `e2e/materials.sh` | Signs the bundle, generates certificate, JWT key pair and trust profiles, renders the TOML, writes the volumes |
| `e2e/up.sh` | Orchestration with per-step logs and failure dumps |
| `e2e/smoke.sh` | Assertions |
| `e2e/down.sh` | Teardown, with `--volumes` the reset |
| `../scripts/apf-materials.sh` | The signing, certificate and trust-profile functions shared with `deploy/helm/e2e` |

## Work directory, logs, and materials

Everything generated lands in `E2E_WORK` (default `deploy/compose/e2e/.work`,
gitignored):

- `bundle-v1/`, `bundle-v2/`, `bundle-v1.tar.gz`, `bundle-v2.tar.gz`,
  `bundle-v1.digest`, `bundle-v2.digest`: staged and signed bundle revisions;
  `bundle-v1/bundle` is what `compose.yaml` bind-mounts. Revision 2 is
  revision 1 with `policy_revision: 2`, plus whatever `BUNDLE_V2_TRANSFORM`
  changes.
- `http-bearer-token`: the policy-service HTTP token, generated once and
  copied into the `apf-secrets` volume.
- `tls/apf.crt`, `tls/apf.key`: the APF serving certificate (RSA 2048,
  365 days, `CA:FALSE`, `serverAuth`, SANs `localhost`,
  `host.openshell.internal`, `127.0.0.1`).
- `openshell-jwt/{signing.pem,public.pem,kid}`: the OpenShell extension-JWT
  key pair (Ed25519) the gateway signs with.
- `trust-interceptor.toml`, `trust-middleware.toml`: one trust profile per
  listener.
- `openshell-gateway.toml`: the environment-adjusted copy of the committed
  TOML variant that the overlay mounts.
- `openshell-state/`: the OpenShell gateway's database and driver state
  (`OPENSHELL_STATE_DIR`).
- `pips.yaml`: the provider registration as loaded by the gateway.
- `logs/<step>.log`: the output of every `up.sh` step; `logs/` also holds the
  gateway log with colour codes stripped, the evaluate responses, the sandbox
  JSON and the audit tails saved by `smoke.sh`.

Volume contents, all owned by 65532: `apf-secrets` holds `http-bearer-token`
and `document-signing.seed` (`0400`); `apf-openshell` holds
`interceptor/{tls.crt,tls.key,trust.toml}`, `middleware/{…}`, `ca.crt` and
`jwt/{signing.pem,public.pem,kid}` (keys `0400`, the rest `0444`); `apf-run`
the two sockets in their own subdirectories; `apf-state` the anti-rollback
counter; `apf-audit` one JSONL file per component.

To swap the bundle to revision 2 (bind sources resolve against the project
directory; pass every overlay that is running so the pod keeps its publishes):

```sh
deploy/compose/e2e/materials.sh bundle v2
APF_BUNDLE_DIR=./e2e/.work/bundle-v2/bundle OPENSHELL_IMAGE_TAG=0.1.3 \
  docker compose --project-directory deploy/compose -f deploy/compose/compose.yaml -f deploy/compose/e2e/compose.openshell.yaml up -d policy-service
```

Starting on revision 1 again afterwards is refused by the counter on
`apf-state`; `down.sh --volumes` is the deliberate reset.

## Environment knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `apf` | compose project; volumes are `<project>_<volume>` |
| `APF_IMAGE_TAG` | `dev` | tag of the local `apf-policy-service` and `apf-policy-gateway` images (`latest` refused) |
| `APF_KEY_ID` / `SIGNING_KEY_ID` | `apf-dev` | document key id and trust-root file stem / bundle signing key id |
| `DEV_KEYS_DIR` | `examples/dev-keys` | development signing seed and trust key |
| `APF_BUNDLE_DIR` / `APF_TRUST_ROOT` | `e2e/.work/bundle-v1/bundle` / `examples/dev-keys/apf-dev.pub` | what `compose.yaml` bind-mounts |
| `BUNDLE_SRC` | `examples/demo-bundle` | bundle source directory with a `*.template.yaml` and its members |
| `BUNDLE_V2_TRANSFORM` | unset | executable that receives the staged revision-2 directory and edits members before signing |
| `OPENSHELL_IMAGE_TAG` | `0.1.3` | gateway, supervisor and sandbox runtime image tag (`latest` refused) |
| `OPENSHELL_IMAGE_REGISTRY` | `ghcr.io/nvidia/openshell` | registry of those images |
| `OPENSHELL_GATEWAY_ID` | `apf-compose` | `gateway_jwt.gateway_id`, the issuer suffix, the audiences and the sandbox label |
| `OPENSHELL_COMPUTE_DRIVER` | `docker` | `docker` or `podman`: the TOML variant and the engine driving sandboxes |
| `CONTAINER_SOCKET` | `/var/run/docker.sock` | engine API socket mounted into the OpenShell gateway |
| `OPENSHELL_STATE_DIR` | `e2e/.work/openshell-state` (the overlay alone: `/var/lib/openshell`) | gateway state, bind-mounted at the same path inside the container; an absolute path. Set it in `.env` to the directory the harness used before recreating `openshell-gateway` by hand |
| `OPENSHELL_GATEWAY_TOML` | `e2e/.work/openshell-gateway.toml` | rendered gateway TOML the overlay mounts |
| `OPENSHELL_PORT` / `OPENSHELL_HEALTH_PORT` | `8080` / `8081` | gateway gRPC and health, published on `127.0.0.1` |
| `APF_ADMISSION_PORT` / `APF_EGRESS_PORT` | `18081` / `9099` | sandbox admission listener (pod-internal) and egress request policy listener (published on `127.0.0.1`) |
| `SANDBOX_IMAGE` | `ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:e29a8e98…` | default sandbox image; must define the `sandbox` user the demo policy names |
| `GRPCURL_IMAGE` | `fullstorydev/grpcurl@sha256:085e183c…` (v1.9.3) | grpcurl for the socket decision |
| `OPENSHELL_CLI` | `E2E_WORK/openshell` or `deploy/helm/e2e/.work/openshell` if present, else `openshell` on `PATH` | OpenShell CLI 0.1.3 used by `smoke.sh` |
| `APF_COMPILE` | `target/release/apf-compile` | bundle signing tool |
| `E2E_WORK` | `deploy/compose/e2e/.work` | work directory |
| `PIP_CONFIG_SRC` | unset (lane off) | provider registration; `deploy/helm/e2e/fixtures/pip/pips.yaml` turns the lane on with the in-repo stub |
| `PIP_STUB_SRC` / `PIP_STUB_IMAGE` | `deploy/helm/e2e/fixtures/pip/stub.py` / `python:3.12-slim` | script and image of the `pip-stub` sidecar |
| `PIP_STUB_PORT` / `PIP_STUB_HEALTH_PATH` | `19500` / `/healthz` | loopback port the stub listens on and the path that must answer 200 |
| `WITH_OPENSHELL` | `up.sh --openshell` sets it; otherwise detected from the running project | include the OpenShell overlay |
| `KEEP_SANDBOX` | unset | `1` keeps the test sandbox after `smoke.sh` |

## Container engines

- **Docker Desktop (macOS)** is where this stack was verified, with the
  OpenShell Docker driver and the default sandbox image. The supervisor
  containers OpenShell starts run with host networking inside the Docker
  Desktop VM, and `grpc_endpoint = "http://127.0.0.1:<port>"` in the driver
  table makes the driver point their `host.openshell.internal` alias at
  loopback; the pod's `127.0.0.1` publishes are bound inside that VM too, so
  the supervisor reaches the gateway and the egress listener through them. The
  OpenShell gateway container runs as `user: "0"`, the upstream
  Docker-outside-of-Docker requirement for the engine socket; nothing else
  was needed. The state bind must be under a directory Docker Desktop shares
  with the VM (`/Users`, `/tmp`, …), which the default under `e2e/.work` is.
- **Docker Engine (Linux)**: the same files; `OPENSHELL_STATE_DIR` may be
  `/var/lib/openshell` when the host user can create it.
- **Rootless Podman** through the Docker-compatible API socket:
  `systemctl --user enable --now podman.socket`,
  `export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock`, then
  `CONTAINER_SOCKET=$XDG_RUNTIME_DIR/podman/podman.sock OPENSHELL_COMPUTE_DRIVER=podman`.
  `config/openshell-gateway.podman.toml` pins `host_gateway_ip = "127.0.0.1"`
  because the Podman driver writes `host.openshell.internal` into the
  supervisor from that value, and Podman's default is not loopback. Inside
  the user namespace UID 65532 maps through the subordinate range; the files
  the throwaway runs write stay readable by the runtime containers. This lane
  is not yet exercised by the harness.

Published ports are checked before the OpenShell overlay comes up: a port held
by a container of another project or by a host process is reported with the
knob that moves the publish (`OPENSHELL_PORT`, `OPENSHELL_HEALTH_PORT`,
`APF_EGRESS_PORT`); the project's own pod from an earlier run is recreated by
compose.

## Notes

- Fresh named volumes are root-owned, like the directories the images create
  at `/run/apf`, `/var/lib/apf` and `/etc/apf`, so `materials.sh` hands them
  to 65532 with a root throwaway run of the policy-service image before the
  first write. Having the Dockerfiles create those directories owned by 65532
  (and run the binaries as that user) would make the step unnecessary; that is
  a Dockerfile follow-up.
- The OpenShell Docker driver resolves the `run_as_user` of the injected
  SandboxPolicy against the pinned sandbox image and refuses an image without
  that user. `examples/demo-bundle` names `sandbox`, which
  `nvcr.io/nvidia/base/ubuntu:24.04` (OpenShell's default) lacks, so
  `SANDBOX_IMAGE` defaults to the OpenShell community base image pinned by
  digest. The Kubernetes path verified by the Helm harness does not perform
  this check.
- grpcurl dials the socket through the `unix:///path` target form; its `-unix`
  flag does not take effect in v1.9.3.
- The development signing key and trust root under `examples/dev-keys` are
  for this harness only.
- Not a production compose: the OpenShell gateway runs as root with the
  engine socket, the gateway is plaintext with unauthenticated users, and the
  APF images still run as root outside this stack.

## Optional: policy information provider lane

Off by default. Turning it on proves that the gateway starts with a provider
registration and reaches a loopback provider in the pod namespace:

```sh
PIP_CONFIG_SRC=deploy/helm/e2e/fixtures/pip/pips.yaml deploy/compose/e2e/up.sh --openshell
```

`materials.sh` stages the registration into `e2e/.work/pips.yaml`, `up.sh`
layers `e2e/compose.pip.yaml` (the `pip-stub` sidecar in the pod namespace and
`APF_PIP_CONFIG=/etc/apf/pip/pips.yaml` on the policy gateway), and `smoke.sh`
adds check 8. The gateway accepts plain-`http` provider URLs on loopback only,
so the stub shares the pod's network namespace at `http://127.0.0.1:19500`; a
provider outside the pod must be served over HTTPS, with `endpoint.tls` in the
registration carrying a private CA and client certificate when needed.

## Composing a demo on top

The stack carries no demo content. A demo points the knobs above at its own
material and reuses the scripts unchanged:

```sh
APF_DIR=/path/to/apf
BUNDLE_SRC=/path/to/demo/bundle \
BUNDLE_V2_TRANSFORM=/path/to/demo/bundle-v2.sh \
PIP_CONFIG_SRC=/path/to/demo/pips.yaml \
PIP_STUB_SRC=/path/to/demo/provider-mock.py \
PIP_STUB_HEALTH_PATH=/demo/state \
SANDBOX_IMAGE=/the/demo/sandbox/image \
  "$APF_DIR/deploy/compose/e2e/up.sh" --openshell
```

The stub script must accept `--port`, bind `127.0.0.1`, and answer
`PIP_STUB_HEALTH_PATH` with 200; the registration must use
`http://127.0.0.1:<PIP_STUB_PORT>` URLs.
