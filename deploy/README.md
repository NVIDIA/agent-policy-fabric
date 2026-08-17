# deploy/

Container images and local development stack for APF services.

## Structure

```text
deploy/
├── docker-compose.yml         # Local dev stack (policy-service + policy-gateway)
├── apf-policy-service/
│   └── Dockerfile             # PAP image
└── apf-policy-gateway/
    └── Dockerfile             # Local PDP image
```

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

## OpenShell middleware security in the dev stack

The compose task publishes the middleware only on host loopback at `127.0.0.1:9099`, and the native task binds that address directly. Both explicitly set `APF_OPENSHELL_MIDDLEWARE_ALLOW_INSECURE_TRANSPORT=true`. This is the OpenShell protocol's total opt-out from extension TLS and caller authentication. Use it only for trusted local development or isolated research, and configure the matching OpenShell registration with `allow_insecure_transport = true`.

An authenticated deployment must remove the insecure setting and provide all of these settings together:

- `APF_OPENSHELL_MIDDLEWARE_ADDR`
- `APF_OPENSHELL_MIDDLEWARE_AUTH_TRUST_FILE`
- `APF_OPENSHELL_MIDDLEWARE_TLS_CERT_FILE`
- `APF_OPENSHELL_MIDDLEWARE_TLS_KEY_FILE`

Mount the trust profile, certificate chain, and private key read-only into the policy-gateway container. Each mount must resolve directly to a regular file rather than a symlink, directory, FIFO, socket, device, or other special file. The trust profile and certificate may be group/world readable but must not be group/world writable. The private key must have no group or world permission bits; use mode `0600` or `0400`. The gateway checks the opened inode, so changing a path after startup inspection cannot substitute a different file for the bytes it reads.

The TLS certificate must match the hostname in the OpenShell middleware endpoint. The trust profile verifies OpenShell extension JWTs and is not the same as the APF bundle keys mounted at `/app/keys` or the policy-service provenance JWKS. The gateway parses the certificate and private key during preflight before any listener reports ready.

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
| `127.0.0.1:18202` | policy-gateway | Interceptor gRPC (OpenShell gateway connects here) |
| `127.0.0.1:9099`  | policy-gateway | Middleware gRPC (explicitly insecure local research mode) |

## Signing bundles

The dev bundle (`examples/demo-bundle/demo-bundle.yaml`) is pre-signed and committed.
Re-sign after changing any policy member file or template:

```fish
mise run sign-bundle
```

Signing key: `examples/dev-keys/apf-dev.seed` (committed; dev only).
See `examples/dev-keys/README.md` for key format and rotation instructions.
