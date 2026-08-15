# apf-policy-service

The APF Policy Administration Point (PAP). Compiles policy bundles into
substrate-native projections, signs them, and serves them to gateways on demand.

## What it does

1. Loads a signed policy bundle at startup (or polls an HTTP source for updates)
2. Compiles `PolicyRule`, `SandboxPolicy`, `Provider`, and other bundle members
   into substrate projections via registered `Projector` implementations
3. Serves projections over gRPC (`PolicyService/GetDocument`) and optionally HTTP
4. Mints a provenance JWT on every `GetDocument` response so gateways can verify
   the projection they receive hasn't been tampered with

The service **never evaluates requests** — that is the gateway's responsibility.

## Subcommands

```
apf-policy-service serve     # run the daemon
apf-policy-service keygen    # generate an Ed25519 signing keypair
```

## Key flags (serve)

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--bundle-path` | `APF_BUNDLE_PATH` | — | Signed bundle YAML to load at startup |
| `--trust-root-dir` | `APF_TRUST_ROOT_DIR` | `./trust-roots` | Directory of `*.pub` trust root keys |
| `--socket` | `APF_SOCKET` | `/run/apf/policy-service.sock` | UDS socket for gRPC |
| `--document-signing-key` | `APF_DOCUMENT_SIGNING_KEY` | ephemeral | Ed25519 seed file for provenance JWTs |
| `--document-key-id` | `APF_DOCUMENT_KEY_ID` | `apf-dev` | Key ID stamped on provenance JWTs |
| `--policy-source` | `APF_POLICY_SOURCE` | `local` | `local` or `http` |
| `--bundle-source-url` | `APF_BUNDLE_SOURCE_URL` | — | Bundle URL (HTTP mode) |
| `--http-addr` | `APF_HTTP_ADDR` | disabled | Enable HTTP surface (health, documents, JWKS) |
| `--http-bearer-token-file` | `APF_HTTP_BEARER_TOKEN_FILE` | — | Required if `--http-addr` is set; gates the non-ops HTTP routes |

## Architecture

```
Bundle (YAML) → compiler pipeline → projections
                                         ↓
                                  PolicyService/GetDocument
                                         ↓
                                  apf-policy-gateway
```

See `docs/architecture.md` for the full control/data plane diagram.
See `docs/policy-model.md` for the policy model and document schemas.
