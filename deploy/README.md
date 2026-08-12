# deploy/

Container images and local development stack for APF services.

## Structure

```
deploy/
├── docker-compose.yml         # Local dev stack (policy-service + policy-gateway)
├── apf-policy-service/
│   └── Dockerfile             # PAP image
└── apf-policy-gateway/
    └── Dockerfile             # Local PDP image
```

## Quick start

```bash
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

```bash
mise run dev-native
```

Starts `apf-policy-service` and `apf-policy-gateway` as host processes sharing
Unix sockets under a temp directory. Requires the release binaries to be built first.

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
| `127.0.0.1:9099`  | policy-gateway | Middleware gRPC (OpenShell supervisor connects here) |

## Signing bundles

The dev bundle (`examples/demo-bundle/demo-bundle.yaml`) is pre-signed and committed.
Re-sign after changing any policy member file or template:

```bash
mise run sign-bundle
```

Signing key: `examples/dev-keys/apf-dev.seed` (committed; dev only).
See `examples/dev-keys/README.md` for key format and rotation instructions.
