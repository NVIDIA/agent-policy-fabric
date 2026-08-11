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
- No cloud round-trip on the hot path

## Invariants

- The Cedar evaluator runs **in-process**. The gateway fetches the bundle from
  policy-service once (and on refresh), builds a `CedarEvaluator` from it, and
  evaluates every request locally. Do not add a gRPC or HTTP call to
  policy-service on the per-request path — that defeats the purpose of the local
  PDP and reintroduces the latency the gateway was designed to eliminate.
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
