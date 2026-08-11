# apf-policy-service — Agent Instructions

PAP binary. Compiles and serves policy bundles. Never evaluates requests.

## Module map

| Module | Role |
|---|---|
| `config.rs` | TOML + CLI config merge |
| `source/mod.rs` | `PolicySource` trait, `PolicyProjection` |
| `source/local.rs` | `LocalBundleSource` — serves from startup bundle |
| `source/http.rs` | `HttpBundleSource` — polls an HTTP endpoint for bundles |
| `source/resolver.rs` | `PolicyResolver`, `PassthroughResolver`, `ClaimsResolver` |
| `runtime/core.rs` | `PolicyServiceCore` — shared daemon state |
| `runtime/audit.rs` | `PolicyServiceAudit` — audit records for the serving surfaces and bundle lifecycle |
| `runtime/runtime_context.rs` | `RuntimeContext` — caller identity parsing |
| `surfaces/policy_service.rs` | gRPC `PolicyService` handler |
| `surfaces/http.rs` | HTTP surface (health, documents, refresh, JWKS) |

## Invariants

- This crate has no evaluation logic. `apf-policy-eval` is not a dependency.
- `apf-openshell-projector` is registered at startup in `main.rs` via
  `Compiler::new(vec![Box::new(OpenShellProjector)])`. Adding a projector for
  a second runtime means adding it to this vec.
- `DocumentSigner` holds the Ed25519 keypair for provenance JWTs.
  `trust.rs` in `apf-policy-gateway` verifies these tokens.
- `surfaces/http.rs` keeps `GET /.well-known/jwks.json` — do not remove it.

## Adding a new substrate projector

1. Create `crates/apf-openshell-<substrate>/` implementing `apf_compiler::Projector`
2. Add it to `[dependencies]` in `Cargo.toml`
3. Register it in `main.rs`: `Compiler::new(vec![..., Box::new(NewProjector)])`

## Build and test

```bash
cargo build -p apf-policy-service
cargo test -p apf-policy-service
```
