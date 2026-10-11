# apf-policy-gateway — Agent Instructions

Host-side enforcement binary. Two distinct roles:
1. **Local PDP** — evaluates egress requests via Cedar in-process
2. **Sandbox policy projection** — hosts the OpenShell interceptor that fetches
   the compiled SandboxPolicy from policy-service and injects it at sandbox
   admission, establishing network egress rules

## Module map

| Module | Role |
|---|---|
| `engine.rs` | `build_evaluator`, `EvaluatorSender`/`EvaluatorReceiver` (watch channel) |
| `bundle_cache.rs` | `refresh()` — verify + parse + load bundle members |
| `digest_watcher.rs` | Polls `GetDocument` for digest changes; emits `BundleChanged` events |
| `events.rs` | `InterceptorEvent` broadcast channel |
| `trust.rs` | `verify_jwt`, `fetch_ed25519_key_from_jwks`, `spawn_jwks_watcher` |
| `audit.rs` | `PolicyGatewayAudit` — audit records for policy activation and decisions |
| `surfaces/evaluation.rs` | `EvaluationServiceImpl` — tonic handler for `EvaluationService/Evaluate` |
| `pip/config.rs` | `RegistryConfig`/`ProviderRegistration` — the `--pip-config` file model (`providers:` root) and every validation rule |
| `pip/subject.rs` | `SubjectPath`, `project`, `default_subject` — subject projection onto the paths a provider type receives |
| `pip/provider.rs` | `ProviderTransport`, `Lookup`/`LookupResult`, `ProviderError`, `validate_response`, `authorize_peer` |
| `pip/enricher.rs` | `ProviderContextEnricher` — implements `apf_policy_eval::ContextEnricher`: `applies_to` matching, fan-out, provenance, failure mode |
| `pip/grpc.rs` | `GrpcTransport` — the `PolicyInformationService` contract over HTTPS with mTLS or a Unix socket |
| `pip/http.rs` | `HttpTransport` — the `type: http` provider: one GET against a JSON API, record selection, `must_match`, `keep` |

## The two enforcement seams

**Sandbox admission (control plane)** — `apf-openshell-interceptor` crate:
- OpenShell gateway calls `GatewayInterceptorServer` when a sandbox is admitted
- Interceptor calls `PolicyService/GetDocument(kind="openshell.sandbox.v1")` on
  `apf-policy-service` to fetch the compiled `SandboxPolicy` bytes
- Verifies the provenance JWT (JWKS from `--jwks-url`)
- Injects `SandboxPolicy` as `apf.nvidia.com/*` annotations — this sets the
  network egress allowlist for the sandbox lifetime

**Per-request evaluation (data plane)** — `surfaces/evaluation.rs`:
- OpenShell supervisor calls `SupervisorMiddlewareServer` → `EvaluationService/Evaluate`
- Gateway evaluates locally via Cedar against the current bundle
- Returns: allow/deny, body patches, header mutations, findings
- Before the engine runs, the Enrichment stage (`pip/`) consults registered providers through
  `apf_policy_eval::decide` (gRPC surface) or `enrich_or_deny` (middleware, on its blocking thread)
- No cloud round-trip on the hot path

## Invariants

- The Cedar evaluator runs **in-process**. The gateway fetches the bundle from
  policy-service once (and on refresh), builds a `CedarEvaluator` from it, and
  evaluates every request locally. Do not add a gRPC or HTTP call to
  policy-service on the per-request path — that defeats the purpose of the local
  PDP and reintroduces the latency the gateway was designed to eliminate.
  The one sanctioned per-request I/O is the Enrichment stage: budgeted calls to the
  providers registered with `--pip-config`, bounded by `--pip-stage-budget-ms`, with
  the failure mode each registration declares.
- `EvaluatorReceiver` (watch channel) is cloned, not moved, into each handler.
  Readers call `.borrow().clone()` to get the current evaluator Arc.
- On bundle refresh: `bundle_cache::refresh()` → `engine::build_evaluator()` →
  `eval_tx.send()` to hot-swap.
- `--openshell-interceptor-addr` is where this process **listens** (inbound).
  `--openshell-gateway-url` is where this process **connects** (outbound).
  Do not confuse the two.
- The `GatewayInterceptorServer` fetches `SandboxPolicy` from `apf-policy-service`
  (not from a local cache). The network egress rules come from the compiled
  projection, not from Cedar evaluation.

## Relationship between the two seams

The interceptor and middleware are complementary:

| Seam | When | What it enforces | Source |
|---|---|---|---|
| Interceptor (admission) | Once per sandbox create | Network destinations the sandbox can reach | Compiled `SandboxPolicy` from policy-service |
| Middleware (per-request) | Every egress request | Whether a specific request is permitted given policy rules and content | Local Cedar evaluation |

A request must pass BOTH: the destination must be in the sandbox's network
policy AND the request must be permitted by the Cedar evaluator.

## OpenShell extension authentication

Both OpenShell-facing surfaces — the `GatewayInterceptorServer` (admission-time,
`--openshell-interceptor-*` flags) and the `SupervisorMiddlewareServer`
(per-request, `--openshell-middleware-*` flags) — share one verifier
(`apf-openshell-auth::ExtensionAuthVerifier`) and one authorization primitive
(`AuthenticationMode::authorize`). They differ only in bind address, trust
file, TLS identity, and which RPCs allow which `ExtensionCallerKind`.

- Extension caller trust is a separate trust domain from bundle and provenance trust. `--openshell-{interceptor,middleware}-auth-trust-file` contains the exact OpenShell issuer, audience, signing `kid`, and Ed25519 public key; never substitute `--trust-root-dir`, `--jwks-url`, or `--document-key-id`.
- Treat `--openshell-{interceptor,middleware}-addr`, the extension trust profile, the TLS certificate, and the TLS key as one authenticated listener configuration. If the listener is enabled, reject missing or partial security settings before bind. If the listener is disabled, reject stray security settings. `apf-policy-gateway/src/main.rs`'s `resolve_secured_listener` is the one place this state machine is implemented — both surfaces call it, so it must not be duplicated per surface.
- Open each security path without following a symlink and validate the opened inode before reading. The trust profile and certificate must be regular files with no group or world write bits. The private key must be a regular owner-only file, normally `0600` or `0400`. Reject directories, FIFOs, sockets, devices, symlinks, and other special files.
- Parse the trust profile, Ed25519 public key, TLS certificate chain, and TLS private key into the server TLS configuration during preflight, before any listener reports ready. Do not fall back to plaintext or expose partial readiness after an open, permission, parse, key, or TLS configuration failure.
- The verifier accepts one bearer credential, requires the OpenShell extension JOSE type and exact configured issuer/audience/key ID, and inserts the verified caller into request extensions before dispatch.
- Authorize RPCs by caller kind, per surface:
  - Middleware: `Describe` allows gateways and supervisors, `ValidateConfig` allows gateways only, `EvaluateHttpRequest` allows supervisors only. Before using request context, require the supervisor token's sandbox ID to match `HttpRequestEvaluation.context.sandbox_id`.
  - Interceptor: `Describe`, `SnapshotProviderProfiles`, and `Evaluate` all allow gateways only — the interceptor is exclusively called by the OpenShell gateway at admission time, so there is no supervisor caller to authorize and no sandbox-ID binding concept on this surface.
- In authenticated mode, `MiddlewareManifest.expected_audience`/`InterceptorManifest.expected_audience` is the configured audience. An empty audience is reserved for explicit insecure mode.
- `--openshell-{interceptor,middleware}-allow-insecure-transport` is a total opt-out from TLS and caller authentication for trusted local development or isolated research. It must be explicit, cannot be combined with authenticated settings, and must emit a startup warning.

## Adding capabilities

To add a new enforcement capability (e.g. a response inspection hook):
1. Create `crates/apf-openshell-<thing>/` implementing the relevant OpenShell
   service trait
2. Add it as a dep in gateway's `Cargo.toml`
3. Add a CLI flag for its bind address
4. Spawn it into the `tasks` join-set in `main.rs`

## Build and test

```bash
cargo build -p apf-policy-gateway
cargo test -p apf-policy-gateway
```
