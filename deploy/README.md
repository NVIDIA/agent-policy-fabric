# deploy/

Container images, Kubernetes Helm chart, local development stack, and host
(systemd) deployment for APF services.

## Structure

```text
deploy/
├── docker/
│   ├── docker-compose.yml     # Local dev stack (policy-service + policy-gateway)
│   ├── apf-policy-service/
│   │   └── Dockerfile         # PAP image
│   └── apf-policy-gateway/
│       └── Dockerfile         # Local PDP image
├── helm/apf/                 # Generic Kubernetes chart
└── systemd/                   # Host deployment (systemd units, sysusers, polkit)
    └── SECURITY.md            # Host deployment security requirements — read before deploying
```

For Kubernetes, see `helm/apf/README.md`. The chart contains no cluster or
organization-specific secret integration; keep those values in the deployment
repository. For a bare-host deployment (not containers), see `systemd/README.md` and,
before deploying, `systemd/SECURITY.md`. The `docker/` stack is local-dev
only (loopback-bound, dev-only signing keys, OpenShell-facing surfaces
running with caller authentication explicitly opted out) and doesn't need
a separate security document — see the comments at the top of
`docker/docker-compose.yml`.

## Quick start

```fish
# Sign the dev bundle (first time or after policy changes)
mise run sign-bundle

# Build images and start both services
mise run dev

# Tail logs
mise run dev-logs

# Stop
mise run dev-down
```

## Native (no Docker)

For faster iteration during development:

```fish
mise run dev-native
```

Starts `apf-policy-service` and `apf-policy-gateway` as host processes sharing Unix sockets under a temp directory. Requires the release binaries to be built first.

## OpenShell extension authentication in the dev stack

The compose task publishes the interceptor and middleware only on host loopback at `127.0.0.1:18202`/`127.0.0.1:9099`, and the native task binds those addresses directly. Both explicitly set `APF_OPENSHELL_INTERCEPTOR_ALLOW_INSECURE_TRANSPORT=true`/`APF_OPENSHELL_MIDDLEWARE_ALLOW_INSECURE_TRANSPORT=true`. This is the OpenShell protocol's total opt-out from extension TLS and caller authentication, independently settable per surface. Use it only for trusted local development or isolated research, and configure the matching OpenShell registration with `allow_insecure_transport = true`.

An authenticated deployment must remove the insecure setting for a surface and provide all of these settings together (shown for middleware; the interceptor equivalents replace `MIDDLEWARE` with `INTERCEPTOR`):

- `APF_OPENSHELL_MIDDLEWARE_ADDR`
- `APF_OPENSHELL_MIDDLEWARE_AUTH_TRUST_FILE`
- `APF_OPENSHELL_MIDDLEWARE_TLS_CERT_FILE`
- `APF_OPENSHELL_MIDDLEWARE_TLS_KEY_FILE`

Mount the trust profile, certificate chain, and private key read-only into the policy-gateway container. Each mount must resolve directly to a regular file rather than a symlink, directory, FIFO, socket, device, or other special file. The trust profile and certificate may be group/world readable but must not be group/world writable. The private key must have no group or world permission bits; use mode `0600` or `0400`. The gateway checks the opened inode, so changing a path after startup inspection cannot substitute a different file for the bytes it reads.

The TLS certificate must match the hostname in the OpenShell registration's endpoint. The trust profile verifies OpenShell extension JWTs and is not the same as the APF bundle keys mounted at `/app/keys` or the policy-service provenance JWKS. It's also independent per surface — the interceptor and middleware trust files are not interchangeable even though they share a format. The gateway parses the certificate and private key during preflight before either listener reports ready. See `crates/apf-policy-gateway/README.md` for the full flag reference and `systemd/SECURITY.md` for the production deployment checklist.

## Dockerfile targets

Each Dockerfile has two targets:

| Target | Use | Includes |
|--------|-----|----------|
| `runtime` | Production / CI | Binary + CA certs only |
| `demo` | Local demo stack | Adds `apf-compile` for bundle signing at startup |

## Ports (dev compose)

| Port | Service | Surface |
|------|---------|---------|
| `127.0.0.1:19200` | policy-service | HTTP — health, documents, refresh, JWKS |
| `127.0.0.1:18202` | policy-gateway | Interceptor gRPC (explicitly insecure local research mode) |
| `127.0.0.1:9099`  | policy-gateway | Middleware gRPC (explicitly insecure local research mode) |

## Signing bundles

The dev bundle (`examples/demo-bundle/demo-bundle.yaml`) is pre-signed and committed.
Re-sign after changing any policy member file or template:

```fish
mise run sign-bundle
```

Signing key: `examples/dev-keys/apf-dev.seed` (committed; dev only).
See `examples/dev-keys/README.md` for key format and rotation instructions.
