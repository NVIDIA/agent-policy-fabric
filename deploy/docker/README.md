<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# APF compose stack

Brings APF up on a laptop from a clone with Docker Compose: the policy service
(verifies the signed bundle, serves projections, mints provenance documents)
and the policy gateway (the local decision point) as two hardened containers
sharing one network namespace. `compose.yaml` is APF only. OpenShell is how
the stack is verified, not part of it: the verification harness under `e2e/`
layers a real OpenShell gateway on this file as an overlay
(`e2e/configs/compose/compose.openshell.yaml`) and runs the checks; see
[`e2e/README.md`](../../e2e/README.md). The two Dockerfiles the stack builds
from live next to this file, under `apf-policy-service/` and
`apf-policy-gateway/`.

Topology: this stack runs the policy service and the policy gateway as two
containers in one network namespace sharing a Unix socket (the co-located
model), the same shape as the Helm chart. The target deployment separates
them: the policy service runs centrally and serves many gateways over the
network, and each policy gateway runs next to the OpenShell gateway it
governs, or centrally as well when latency and the features in use allow.
That split needs the networked policy-service transport, which does not exist
yet, so this stack does not offer it.

What the standalone stack is:

- `pod`: a pause container that owns the network namespace, read-only with
  every capability dropped. The base file publishes no ports; the policy
  service binds loopback inside the namespace and the gateway serves a Unix
  socket.
- `policy-service`: `apf-policy-service serve` with the flags the chart passes
  for the local bundle source; HTTP on `127.0.0.1:19200` with a bearer token,
  the signed bundle and the trust root bind-mounted read-only, the anti-rollback
  counter on the `apf-state` volume, audit files on `apf-audit`.
- `policy-gateway`: `apf-policy-gateway` serving `EvaluationService/Evaluate`
  on `/run/apf/policy-gateway/policy-gateway.sock` (volume `apf-run`), fetching
  the policy set over the service socket and JWKS over loopback. Its two
  OpenShell listeners are off until the overlay enables them.
- Both run as `65532`, read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, a private size-bounded `/tmp`.

## Verification

`e2e/with-compose-stack.sh` brings this stack up, runs a suite against it and
tears it down:

```sh
e2e/with-compose-stack.sh e2e/suites/smoke.sh               # APF alone
e2e/with-compose-stack.sh --openshell e2e/suites/smoke.sh   # with an OpenShell gateway admitting a sandbox through APF
```

`mise run dev` builds the two images first and keeps the stack running
(`mise run dev-logs`, `mise run dev-down`). Prerequisites, the OpenShell
journey, the signing walkthrough, the smoke checks and the knobs are in
`e2e/README.md`; `e2e/suites/parity.sh` keeps the flags in `compose.yaml`
identical to the chart's.

## By hand, with bare `docker compose`

Bare `docker compose` commands read `.env` from the project directory, which
is the directory of the first `-f` file, `deploy/docker`; the overlays'
relative paths resolve against it too. Every command below runs from the
repository root. Copy `.env.example` to `.env` first; its values equal the
harness defaults, so a knob changed in one file is changed in the other.

```sh
cp deploy/docker/.env.example deploy/docker/.env
```

1. Stage the inputs without starting anything:

   ```sh
   e2e/with-compose-stack.sh --prepare               # APF alone
   e2e/with-compose-stack.sh --prepare --openshell   # also the overlay's certificate, key pair, trust profiles and TOML
   ```

   This signs `examples/demo-bundle` into
   `e2e/.work/compose/bundle-v1/bundle` (what `.env` points `APF_BUNDLE_DIR`
   at; `compose.yaml` alone defaults to `./bundle`), runs
   `docker compose up --no-start` so compose creates the project's volumes,
   hands the fresh volumes to user 65532 through a root throwaway run of the
   policy-service image, and writes the bearer token and the document signing
   seed into `apf-secrets` through a second throwaway run as 65532
   (`docker run --rm -i --user 65532:65532 --entrypoint sh apf-policy-service:dev`),
   so both land as `0400` files owned by 65532 on every engine.
2. Start the stack:

   ```sh
   docker compose -f deploy/docker/compose.yaml up -d
   ```

   Compose starts the pod, then the policy service to healthy
   (`curl -fsS http://127.0.0.1:19200/readyz` inside the namespace), then the
   gateway to healthy (its socket exists).
3. Proofs, all from inside the namespace or over the socket volume because
   nothing is published:

   ```sh
   docker compose -f deploy/docker/compose.yaml logs policy-service | grep 'bundle verified and loaded'
   docker compose -f deploy/docker/compose.yaml exec policy-service sh -c 'curl -fsS -H "Authorization: Bearer $(cat /etc/apf/secrets/http-bearer-token)" http://127.0.0.1:19200/v1/documents/openshell.sandbox.v1'
   docker run --rm -i --user 65532:65532 -v apf_apf-run:/run/apf -v "$PWD/contracts/proto:/proto:ro" \
     fullstorydev/grpcurl@sha256:085e183ca334eb4e81ca81ee12cbb2b2737505d1d77f5e33dabc5d066593d998 \
     -plaintext -import-path /proto -proto nvidia/agent_policy_fabric/pdp/v1alpha1/pdp.proto \
     -d @ unix:///run/apf/policy-gateway/policy-gateway.sock \
     nvidia.agent_policy_fabric.pdp.v1alpha1.EvaluationService/Evaluate < examples/evaluate/deny.json
   docker compose -f deploy/docker/compose.yaml exec policy-gateway tail -n 1 /var/log/apf/audit/apf-policy-gateway-audit.jsonl
   ```

   The grpcurl container attaches only the socket volume and the proto sources
   and runs as 65532, which the gateway's peer-credential check requires. The
   request files under `examples/evaluate/` give `DECISION_DENY` and
   `DECISION_ALLOW` against the demo bundle; the audit line carries the same
   `policy_digest`.
4. With the OpenShell overlay (after `--prepare --openshell`): the gateway's
   state directory must be an absolute path, so set it in `.env` to the
   harness directory, then pass every overlay on each command so the pod
   keeps its publishes. The OpenShell CLI is the one the harness prerequisites
   installed at `e2e/.work/openshell`:

   ```sh
   echo "OPENSHELL_STATE_DIR=$PWD/e2e/.work/compose/openshell-state" >> deploy/docker/.env
   docker compose -f deploy/docker/compose.yaml -f e2e/configs/compose/compose.openshell.yaml up -d
   e2e/.work/openshell --gateway-endpoint http://127.0.0.1:8080 --gateway-insecure gateway info
   e2e/.work/openshell --gateway-endpoint http://127.0.0.1:8080 --gateway-insecure sandbox create --name demo --detach -- sleep 3600
   e2e/.work/openshell --gateway-endpoint http://127.0.0.1:8080 --gateway-insecure sandbox get demo -o json | grep apf.nvidia.com/
   docker compose -f deploy/docker/compose.yaml -f e2e/configs/compose/compose.openshell.yaml logs openshell-gateway | grep 'gateway interceptor evaluated'
   docker compose -f deploy/docker/compose.yaml -f e2e/configs/compose/compose.openshell.yaml exec policy-gateway tail -n 5 /var/log/apf/audit/apf-policy-gateway-interceptor-audit.jsonl
   ```

5. Swap the bundle to revision 2; `--prepare` stages both revisions. Pass the
   same `-f` files as the running stack and `--no-deps`, so compose recreates
   only the policy service and leaves the pod's publishes alone:

   ```sh
   APF_BUNDLE_DIR=$PWD/e2e/.work/compose/bundle-v2/bundle docker compose -f deploy/docker/compose.yaml -f e2e/configs/compose/compose.openshell.yaml up -d --no-deps policy-service
   ```

   Starting on revision 1 again afterwards is refused by the counter on
   `apf-state`; `e2e/with-compose-stack.sh --down --volumes` is the
   deliberate reset.
6. Tear down:

   ```sh
   docker compose -f deploy/docker/compose.yaml -f e2e/configs/compose/compose.openshell.yaml down
   ```

   `--volumes` also resets the counter, the secrets and the OpenShell
   material. `e2e/with-compose-stack.sh --down --volumes` does the same and
   first deletes the sandboxes through the gateway, then (Docker driver)
   sweeps the sandbox containers and volumes labelled with the run's
   namespace.

## The OpenShell overlay

`e2e/configs/compose/compose.openshell.yaml` adds, without touching the base
semantics:

- on `pod`: the alias `host.openshell.internal -> 127.0.0.1` and the publishes
  `127.0.0.1:8080` (gateway gRPC), `127.0.0.1:8081` (gateway health) and
  `127.0.0.1:9099` (egress request policy, for the host-network supervisor);
- on `policy-gateway`: the sandbox admission listener on `0.0.0.0:18081` and
  the egress request policy listener on `0.0.0.0:9099`, each with its TLS
  certificate and trust profile from the `apf-openshell` volume, plus
  `--openshell-gateway-url`; its healthcheck becomes a TCP connect to the
  egress listener, the signal the chart's readiness probe uses;
- `openshell-gateway`: OpenShell in the pod namespace, started with
  `--config /etc/openshell/gateway.toml` (the rendered copy of
  `e2e/configs/gateway/openshell-gateway.<driver>.toml`), the engine socket
  mounted at `/run/container-engine/engine.sock`, its state bind-mounted at
  the same path inside and outside the container (`OPENSHELL_STATE_DIR`,
  required), its extension-JWT key pair and `ca.crt` from the `openshell-jwt`
  volume, and `depends_on: policy-gateway: service_healthy`, because the
  gateway calls `Describe` on every registered extension at startup and
  fails closed when one is unreachable.

The OpenShell gateway runs as `user: "0"`, the Docker-outside-of-Docker
requirement for the engine socket, and plaintext with unauthenticated users:
a verification fixture, not a deployment, which is also why it has
`restart: on-failure` and does not come back by itself after an engine
restart. Trust between the two sides and the provider lane
(`e2e/configs/compose/compose.pip.yaml`) are described in `e2e/README.md`.

## Files

| File | Role |
| --- | --- |
| `deploy/docker/compose.yaml` | APF standalone: `pod`, `policy-service`, `policy-gateway`, the four named volumes |
| `deploy/docker/.env.example` | Pinned tags, engine socket, driver, published ports, grpcurl image; copy to `.env` |
| `e2e/configs/compose/compose.openshell.yaml` | OpenShell overlay: publishes, listeners on the policy gateway, the OpenShell gateway |
| `e2e/configs/compose/compose.pip.yaml` | Provider lane: the `pip-stub` sidecar and `APF_PIP_CONFIG` on the policy gateway |
| `e2e/configs/gateway/openshell-gateway.docker.toml`, `.podman.toml` | OpenShell gateway configuration with the APF registration, one per compute driver |

Volume contents: `apf-secrets` holds `http-bearer-token` and
`document-signing.seed` (`0400`, owned by 65532); `apf-openshell` (overlay,
mounted by the policy gateway only) holds
`interceptor/{tls.crt,tls.key,trust.toml}`, `middleware/{…}` and `ca.crt`
(keys `0400`, the rest `0444`, owned by 65532); `openshell-jwt` (overlay,
mounted by the OpenShell gateway only) holds `jwt/{signing.pem,public.pem,kid}`
and `ca.crt` (`signing.pem` `0400`, the rest `0444`, owned by root, the
gateway's user), so neither party holds the other's private key; `apf-run`
the two sockets in their own subdirectories; `apf-state` the anti-rollback
counter; `apf-audit` one JSONL file per component, all owned by 65532.

## Container engines

`compose.yaml` uses only what the Docker Compose specification and the Docker
API offer in common across engines: named volumes, bind mounts, a tmpfs with
the generic options, `network_mode: service:`, healthchecks.

- **Docker Desktop (macOS)** is where the stack is verified, with the
  OpenShell Docker driver and the default sandbox image. The state bind of the
  OpenShell overlay must be under a directory Docker Desktop shares with its
  VM (`/Users`, `/tmp`, …), which the harness default under `e2e/.work` is.
- **Docker Engine (Linux)**: the same files. Keep `OPENSHELL_STATE_DIR` under
  `e2e/.work`, where the harness default is: the harness empties only a
  state directory there, and a directory elsewhere may belong to another
  OpenShell gateway.
- **Podman** through its Docker-compatible API socket, with
  `OPENSHELL_COMPUTE_DRIVER=podman` selecting
  `e2e/configs/gateway/openshell-gateway.podman.toml`. Two sockets are
  involved: `DOCKER_HOST` is the API socket the `docker` CLI talks to, and
  `CONTAINER_SOCKET` the path the engine resolves when it bind-mounts the
  socket into the OpenShell gateway, which differs from the host path with a
  Podman machine. What the harness found on Podman is recorded in
  `e2e/README.md` under "Container engines".

## Notes

- Fresh named volumes are root-owned, like the directories the images create
  at `/run/apf`, `/var/lib/apf` and `/etc/apf`, so the harness hands them to
  65532 with a root throwaway run of the policy-service image before the
  first write. Having the Dockerfiles create those directories owned by 65532
  (and run the binaries as that user) would make the step unnecessary; that is
  a Dockerfile follow-up.
- The OpenShell Docker driver resolves the `run_as_user` of the injected
  SandboxPolicy against the pinned sandbox image and refuses an image without
  that user. `examples/demo-bundle` names `sandbox`, which
  `nvcr.io/nvidia/base/ubuntu:24.04` (OpenShell's default) lacks, so
  `SANDBOX_IMAGE` defaults to the OpenShell community base image pinned by
  digest. The Kubernetes path does not perform this check.
- grpcurl dials the socket through the `unix:///path` target form; its `-unix`
  flag does not take effect in v1.9.3.
- The development signing key and trust root under `examples/dev-keys` are
  for verification only.
- Not a production compose: the OpenShell gateway runs as root with the
  engine socket, the gateway is plaintext with unauthenticated users, and the
  APF images still run as root outside this stack.
