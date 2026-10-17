# APF — Agent Instructions

APF (Agent Policy Fabric) is the policy layer for agentic workloads. It decides what
AI agents may do — at sandbox admission and on every request — and hands those decisions
to the sandbox runtime, which enforces them. Tool invocation and credential handling are
out of scope for this repository and belong to the network egress gateway.

---

## Crates

| Crate | Kind | Role |
|---|---|---|
| `apf-types` | lib | `BundleSigner`/`BundleVerifier` traits, `Decision`, `Obligation`, shared vocabulary |
| `apf-audit` | lib | `apf.audit.event.v1` schema, typed event builders, redaction, sanitization, JSONL emitter |
| `apf-bundle` | lib | `Bundle`, `verify_bundle`, `TrustStore`, `CounterStore`, Ed25519 default signing impl |
| `apf-policy-eval` | lib | `Evaluator` trait, `EvalInput`/`EvalResult`, Cedar engine, enrichment stage contract (`ContextEnricher`, `EvalInput::context_attributes`) |
| `apf-compiler` | lib | Bundle compilation: frontend, passes, merge, `Projector` trait |
| `apf-proto` | lib | Generated gRPC bindings from `contracts/proto/` |
| `apf-policy-client` | lib | gRPC client for `PolicyService` |
| `apf-policy-service` | **service** | PAP — verify, project, store, serve signed bundles. Never evaluates requests; does not author or sign (that is `apf-compile`, run offline). |
| `apf-policy-gateway` | **service** | Host-side policy agent — sandbox policy projection, local PDP, and provider enrichment (`pip/`, registered with `--pip-config`). |
| `apf-openshell-projector` | **adapter** | Compiles APF policy IR into OpenShell-native projections; registered in `apf-policy-service`. |
| `apf-openshell-interceptor` | **adapter** | OpenShell gateway interceptor; runs inside `apf-policy-gateway` at sandbox admission. |
| `apf-openshell-middleware` | **adapter** | OpenShell supervisor middleware; runs inside `apf-policy-gateway` per egress request. |
| `apf-openshell-auth` | **adapter** (leaf) | Extension-JWT caller verification shared by the interceptor and middleware. |
| `apf-compile` | **service** | CLI for offline bundle compilation and signing; runs in the enterprise policy-authoring + publish path, not on the host. |

**Service** = `[[bin]]` target AND `publish = false` in `Cargo.toml`.  
**Adapter** = name prefix `apf-openshell-` (or `apf-<runtime>-*` for future runtimes). Library crates cannot depend on adapters; service binaries can.

---

## Before modifying

| Changing | Read first |
|---|---|
| Any crate or wire contract | `docs/about/architecture.mdx` — components, trust boundary, control/data plane split |
| `contracts/proto/` | `docs/about/governed-path.mdx` (flows that use the wire contracts), `docs/reference/adapter-contracts.mdx` (the OpenShell wire contracts), and the `buf lint` / `buf breaking` rules below |
| `crates/apf-openshell-*` | `docs/integrations/openshell/index.mdx` — OpenShell seams and adapter responsibilities |
| Any service crate | Run `cargo xtask dag-guard` after changes |

---

## Build and test

```bash
mise install --locked        # pinned tools: buf, protoc, Python, cargo-deny, cargo-nextest
mise run ci                  # every check CI runs on a pull request (tasks/*.toml)
cargo build                  # open-source build, no private features
cargo nextest run            # full test suite
cargo xtask dag-guard        # verify DAG invariants
cargo xtask vendor-protos --check   # vendored protos match contracts/third_party/pins.toml
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cargo-deny --locked check licenses bans sources -D no-license-field
buf lint contracts/          # proto contracts
```

---

## DAG invariants

Dependency direction: `contracts/ → crates/<lib> → crates/<service> → crates/<adapter>`

**Forbidden — dag-guard fails the pull request:**
- Service crate path-depending on another service crate
- Library crate path-depending on any service or adapter crate
- Adapter crate path-depending on a *non-leaf* adapter crate — a leaf adapter
  (no adapter deps of its own, e.g. `apf-openshell-auth`) may be shared by
  other adapters; two business-logic adapters may not depend on each other directly
- `openshell_*` imports in library crate source
- `yaml_sigil_*` imports outside `apf-bundle`'s signing backend (`crates/apf-bundle/src/signing/yaml_sigil.rs`)

---

## Key invariants

**OpenShell adapter crates.** OpenShell types appear only in `crates/apf-openshell-*`.
Adding a second runtime means adding `crates/apf-<runtime>-*` adapter crates —
no changes to shared library or service crates are needed.

**Signing seam.** All signing goes through `BundleSigner`/`BundleVerifier` (in `apf-types`). Default Ed25519 impl is in `apf-bundle`. The yaml-sigil private backend is the only exception and stays feature-gated in `apf-bundle`.

**Org-workflow seam.** Public service binaries must compile without private org dependencies. Org-specific behavior belongs in a private composition binary wired through APF traits — never inlined in the public service crate.

**Extract on second consumer.** Start code in the owning service crate. Extract to a shared library only when a second consumer needs it.

---

## Change rules

- Wire contract change (`contracts/proto/`) — new proto package or `$id` if breaking; `buf breaking` must pass.
- Third-party proto pin change (`contracts/third_party/pins.toml`) — run `cargo xtask vendor-protos`, build, and commit the exported files together with the pin; CI runs `cargo xtask vendor-protos --check`.
- New crate — add to `[workspace] members`; run `cargo xtask dag-guard` before opening a pull request.
- New or updated dependency — `cargo-deny --locked check licenses bans sources -D no-license-field` must pass (`mise run rust:deny:policy`; the cargo-deny version is pinned in `mise.toml`). Only MIT and Apache-2.0 are allowed globally. Any other license needs a per-crate exception in `deny.toml` that lists only the licenses the crate declares, a `licenses/selections.json` entry if its expression is new, and a regenerated `THIRD_PARTY_LICENSES.txt` (`mise run third-party-notices:update`). Never widen the global `allow` list to admit one crate; treat any `deny.toml` edit as a license decision.

---

## Commits

- Format: `feat(apf):`, `fix(apf):`, `docs(apf):`, or component-scoped `feat(policy-gateway):`.
- Copyright header on every new source file — see `CONTRIBUTING.md`; `pre-commit run verify-copyright` adds/updates it for you.
