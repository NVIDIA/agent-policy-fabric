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
| `apf-policy-gateway` | **service** | Host-side policy agent — sandbox policy projection and local PDP. |
| `apf-openshell-projector` | **adapter** | Compiles APF policy IR into OpenShell-native projections; registered in `apf-policy-service`. |
| `apf-openshell-interceptor` | **adapter** | OpenShell gateway interceptor; runs inside `apf-policy-gateway` at sandbox admission. |
| `apf-openshell-middleware` | **adapter** | OpenShell supervisor middleware; runs inside `apf-policy-gateway` per egress request. |

**Service** = `[[bin]]` target AND `publish = false` in `Cargo.toml`.  
**Adapter** = name prefix `apf-openshell-` (or `apf-<runtime>-*` for future runtimes). Library crates cannot depend on adapters; service binaries can.

---

## Before modifying

| Changing | Read first |
|---|---|
| Any crate or wire contract | `docs/architecture.md` — component responsibilities, data flow, control/data plane split |
| `contracts/proto/` | `docs/architecture.md` §4 (sequence diagrams) and the `buf lint` / `buf breaking` rules below |
| `crates/apf-openshell-*` | `docs/architecture.md` §3 — OpenShell seams and adapter responsibilities |
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

Dependency direction: `contracts/ → crates/<lib> → crates/<service> → crates/<adapter>`

**Forbidden — dag-guard fails the pull request:**
- Service crate path-depending on another service crate
- Library crate path-depending on any service or adapter crate
- `openshell_*` imports in library crate source
- `yaml_sigil_*` imports outside `apf-policy-service/src/signing/yaml_sigil_backend.rs`

---

## Key invariants

**OpenShell adapter crates.** OpenShell types appear only in `crates/apf-openshell-*`.
Adding a second runtime means adding `crates/apf-<runtime>-*` adapter crates —
no changes to shared library or service crates are needed.

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
