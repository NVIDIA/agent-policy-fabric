# deploy/

Container images, a Docker Compose stack, a Kubernetes Helm chart, and the
host (systemd) deployment for APF services.

## Structure

```text
deploy/
├── docker/
│   ├── apf-policy-service/
│   │   └── Dockerfile         # PAP image
│   └── apf-policy-gateway/
│       └── Dockerfile         # Local PDP image
├── compose/                   # Docker Compose stack (policy-service + policy-gateway), OpenShell add-on under e2e/
├── helm/apf/                  # Generic Kubernetes chart; helm/e2e/ verifies it on kind
├── scripts/
│   └── apf-materials.sh       # Signing, certificate and trust-profile functions shared by the harnesses
└── systemd/                   # Host deployment (systemd units, sysusers, polkit)
    └── SECURITY.md            # Host deployment security requirements — read before deploying
```

For the compose stack, see `compose/README.md`: it brings APF up on a laptop
with the chart's shape and defaults, and `compose/e2e/` adds a real OpenShell
gateway to verify sandbox admission through APF. For Kubernetes, see
`helm/apf/README.md`. The chart contains no cluster or organization-specific
secret integration; keep those values in the deployment repository. For a
bare-host deployment (not containers), see `systemd/README.md` and, before
deploying, `systemd/SECURITY.md`.

## Quick start

```fish
# Build images, bring the stack up standalone, run the smoke checks
mise run dev

# Tail logs
mise run dev-logs

# Stop (volumes kept)
mise run dev-down
```

`deploy/compose/e2e/up.sh --openshell` adds the OpenShell gateway and admits a
sandbox through APF.

## Native (no Docker)

For faster iteration during development:

```fish
mise run dev-native
```

Starts `apf-policy-service` and `apf-policy-gateway` as host processes sharing Unix sockets under a temp directory. Requires the release binaries to be built first.

## OpenShell extension authentication

The compose stack keeps the OpenShell-facing listeners off until the OpenShell
overlay enables them with TLS and extension-JWT trust profiles; the native task
binds them on loopback with `APF_OPENSHELL_INTERCEPTOR_ALLOW_INSECURE_TRANSPORT=true`/`APF_OPENSHELL_MIDDLEWARE_ALLOW_INSECURE_TRANSPORT=true`. That setting is the OpenShell protocol's total opt-out from extension TLS and caller authentication, independently settable per surface. Use it only for trusted local development or isolated research, and configure the matching OpenShell registration with `allow_insecure_transport = true`.

An authenticated deployment must remove the insecure setting for a surface and provide all of these settings together (shown for middleware; the interceptor equivalents replace `MIDDLEWARE` with `INTERCEPTOR`):

- `APF_OPENSHELL_MIDDLEWARE_ADDR`
- `APF_OPENSHELL_MIDDLEWARE_AUTH_TRUST_FILE`
- `APF_OPENSHELL_MIDDLEWARE_TLS_CERT_FILE`
- `APF_OPENSHELL_MIDDLEWARE_TLS_KEY_FILE`

Mount the trust profile, certificate chain, and private key read-only into the policy-gateway container. Each mount must resolve directly to a regular file rather than a symlink, directory, FIFO, socket, device, or other special file. The trust profile and certificate may be group/world readable but must not be group/world writable. The private key must have no group or world permission bits; use mode `0600` or `0400`. The gateway checks the opened inode, so changing a path after startup inspection cannot substitute a different file for the bytes it reads.

The TLS certificate must match the hostname in the OpenShell registration's endpoint. The trust profile verifies OpenShell extension JWTs and is not the same as the APF bundle keys or the policy-service provenance JWKS. It's also independent per surface — the interceptor and middleware trust files are not interchangeable even though they share a format. The gateway parses the certificate and private key during preflight before either listener reports ready. See `crates/apf-policy-gateway/README.md` for the full flag reference and `systemd/SECURITY.md` for the production deployment checklist.

## Dockerfile targets

Each Dockerfile has two targets:

| Target | Use | Includes |
|--------|-----|----------|
| `runtime` | Production / CI | Binary + CA certs only |
| `demo` | Local demo stack | Adds `apf-compile` for bundle signing at startup |

## Signing bundles

The dev bundle (`examples/demo-bundle/demo-bundle.yaml`) is pre-signed and committed.
Re-sign after changing any policy member file or template:

```fish
mise run sign-bundle
```

Signing key: `examples/dev-keys/apf-dev.seed` (committed; dev only).
See `examples/dev-keys/README.md` for key format and rotation instructions.
The compose and Helm harnesses sign their own copy at setup time with
`deploy/scripts/apf-materials.sh`.
