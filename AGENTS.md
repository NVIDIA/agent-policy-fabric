# APF — Agent Instructions

APF (Agent Policy Fabric) is the policy layer for agentic workloads. It decides what
AI agents may do and enforces those decisions at the network, tool, and credential layer.

---

## Crates

| Crate | Kind | Role |
|---|---|---|
| `apf-types` | lib | `BundleSigner`/`BundleVerifier` traits, `Decision`, `Obligation`, shared vocabulary |
| `apf-bundle` | lib | `Bundle`, `verify_bundle`, `TrustStore`, `CounterStore`, Ed25519 default signing impl |
| `apf-policy-eval` | lib | `Evaluator` trait, `EvalInput`/`EvalResult`, Cedar engine |
| `apf-compiler` | lib | Bundle compilation: frontend, passes, merge, `Projector` trait |
| `apf-proto` | lib | Generated gRPC bindings from `contracts/proto/` |
| `apf-policy-client` | lib | gRPC client for `PolicyService` |
| `apf-policy-service` | **service** | PAP — compile, sign, store, serve bundles. Never evaluates requests. |
| `apf-policy-gateway` | **service** | Local PDP — fetch, verify, evaluate. Serves `EvaluationService/Evaluate` over UDS. |
| `apf-tool-gateway` | **service** | Tool relay — calls gateway for decisions before invoking host tools. |
| `apf-cred-proxy` | **service** | Credential procurement and injection (stub). |
| `runtimes/openshell` | adapter | OpenShell interceptor + middleware. Only place OpenShell types appear. |

**Service** = `[[bin]]` target AND `publish = false` in `Cargo.toml`.

---

## Before modifying

| Changing | Read first |
|---|---|
| Any crate or wire contract | `docs/architecture.md` — component responsibilities, data flow, control/data plane split |
| `contracts/proto/` | `docs/architecture.md` §4 (sequence diagrams) and the `buf lint` / `buf breaking` rules below |
| `runtimes/openshell/` | `runtimes/openshell/AGENTS.md` |
| Any service crate | Run `cargo xtask dag-guard` after changes |

---

## Build and test

```bash
cargo build                  # open-source build, no private features
cargo nextest run            # full test suite
cargo xtask dag-guard        # verify DAG invariants
cargo fmt --check && cargo clippy -- -D warnings && cargo deny check
buf lint contracts/          # proto contracts
```

---

## DAG invariants

Dependency direction: `contracts/ → crates/<lib> → crates/<service> → runtimes/*`

**Forbidden — dag-guard fails the pull request:**
- Service crate path-depending on another service crate
- Library crate path-depending on any service or runtime crate
- `openshell_*` or `runtimes::` imports in library crate source
- `yaml_sigil_*` imports outside `apf-policy-service/src/signing/yaml_sigil_backend.rs`

---

## Key invariants

**OpenShell is a runtime adapter.** OpenShell types live exclusively in `runtimes/openshell/`. Adding a second runtime is `runtimes/foo/` — no changes to libraries or services.

**Signing seam.** All signing goes through `BundleSigner`/`BundleVerifier` (in `apf-types`). Default Ed25519 impl is in `apf-bundle`. The yaml-sigil private backend is the only exception and stays feature-gated in `apf-policy-service`.

**Org-workflow seam.** Public service binaries must compile without private org dependencies. Org-specific behavior belongs in a private composition binary wired through APF traits — never inlined in the public service crate.

**Extract on second consumer.** Start code in the owning service crate. Extract to a shared library only when a second consumer needs it.

---

## Change rules

- Wire contract change (`contracts/proto/`) — new proto package or `$id` if breaking; `buf breaking` must pass.
- New crate — add to `[workspace] members`; run `cargo xtask dag-guard` before opening a pull request.

---

## Commits

- Format: `feat(apf):`, `fix(apf):`, `docs(apf):`, or component-scoped `feat(policy-gateway):`.
- License header on every new Rust file: `// SPDX-License-Identifier: Apache-2.0`.
