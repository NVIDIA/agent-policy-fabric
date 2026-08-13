# APF Architecture

Created: 2026-08-08  Updated: 2026-08-13

**Status:** draft — under review

---

## 1. Component Responsibilities

### `apf-policy-service` — Policy Administration Point (PAP) *(cloud deployment: planned)*

Policy authority for the APF stack. Compiles, signs, stores, and serves policy bundles. Never evaluates requests.

**Current supported deployment:** `apf-policy-service` runs on the same host as `apf-policy-gateway`, serving bundles over a Unix domain socket (`LocalBundleSource` or `HttpBundleSource`). See §7 for the planned cloud-based topology.

| Responsibility | Detail |
|---|---|
| Compile | Transforms `PolicyRule` documents → substrate projections via `compiler/` pipeline |
| Sign | Signs bundles via `BundleSigner` (default Ed25519; optional private backend) |
| Store + serve | `PolicySource` (HttpBundleSource, LocalBundleSource) serves compiled projections |
| gRPC surface | `PolicyService`: `Health`, `GetDocument`, `ListDocuments` |
| HTTP surface | `/health*`, `/v1/documents/*`, `/v1/refresh`, `GET /.well-known/jwks.json` |
| Provenance | Mints JWT (`provenance_token`) on every `GetDocument` response via `DocumentSigner` |
| Variant selection | `PolicyResolver` maps caller runtime context → bundle variant (e.g. `"governed-rw"`) |

### `apf-policy-gateway` — host-side policy agent

The host-side anchor for all APF enforcement. It embeds the local Policy Decision Point (PDP) — fetching and verifying bundles, evaluating every request in-process with no cloud dependency on the hot path — and it hosts the runtime enforcement adapters: sandbox policy projection at admission and per-request egress enforcement (see the OpenShell adapter section below).

| Responsibility | Detail |
|---|---|
| Fetch | Calls `apf-policy-service` via `apf-policy-client` (`GetDocument`) |
| Verify | Runs `apf-bundle::verify_bundle`: signature, manifest hashes, expiry, `runtime_compatibility`, monotonic counter |
| Evaluate | Builds `CedarEvaluator` from bundle; hot-swaps via `arc-swap` on bundle refresh |
| gRPC surface | `EvaluationService`: `rpc Evaluate` over UDS |
| Provenance trust | Verifies `provenance_token` JWT from `GetDocument`; rotates key via JWKS watcher |
| Audit | Bundle lifecycle events; evaluation events (wired in M5 audit milestone) |

### OpenShell — substrate adapter

APF integrates with OpenShell through three adapter crates (`apf-openshell-*`).
Each is scoped to a single concern; together they cover the full lifecycle from
bundle compilation through runtime enforcement.

| Crate | Service | Role |
|---|---|---|
| `apf-openshell-projector` | policy-service | Compiles APF policy IR into OpenShell-native projections (`SandboxPolicy`, provider profiles) at bundle load time |
| `apf-openshell-interceptor` | policy-gateway | At sandbox admission: delivers the compiled `SandboxPolicy` to OpenShell and establishes the sandbox's network egress rules |
| `apf-openshell-middleware` | policy-gateway | At each egress request: enforces the active policy decision (allow/deny, redaction, header mutations) via the OpenShell supervisor hook |

The interceptor and middleware run inside the `apf-policy-gateway` process.
Adding a second runtime substrate means adding a new set of `apf-<runtime>-*`
adapter crates — no changes to the shared library or service crates are required.

### `apf-tool-gateway` — Tool Invocation and Relay

Routes agent tool calls to host tools (CLI processes, remote MCP servers). Calls `apf-policy-gateway` for evaluation decisions before invoking a tool.

| Responsibility | Detail |
|---|---|
| Tool relay | Receives MCP tool calls from agent; routes to `HostTool` definitions |
| Policy check | Calls `EvaluationService/Evaluate` on gateway before each tool invocation |
| HostTool registry | `hosttool-core`, `hosttool-runtime`, `hosttool-remote-mcp` |
| Credential (today) | `hosttool-vault` handles credential fetch; boundary to be extracted to `apf-cred-proxy` |

### `apf-cred-proxy` — Credential Procurement and Injection *(planned)*

See §5 for the planned design. Handles credential lifecycle separately from policy decisions — different trust profile, different availability domain.

---

## 2. Component Diagram

```
  Policy Author ────────▶  apf-policy-service (PAP)
                           • compile / sign / serve
                           • PolicyService gRPC
                           • JWKS endpoint
                                    │ GetDocument (poll)
                                    ▼
                           apf-policy-gateway (host-side policy agent)
                           • verify bundle (apf-bundle)
                           • CedarEvaluator (arc-swap) — local PDP
                           • EvaluationService/Evaluate (UDS)
                           • JWKS trust verification
                          ┌─────────┴──────────────┐
                          │ Evaluate (in-process)   │ SandboxPolicy projection
                          ▼                         ▼
              apf-openshell-middleware   apf-openshell-interceptor
              [OpenShell data plane]     [OpenShell control plane]
              per-request egress         sandbox admission
              (inside gateway process)   (inside gateway process)
                          │
                          ▼
                    Agent egress
                    (tool calls, HTTP requests)
```

---

## 3. Positioning within OpenShell

OpenShell is the first supported runtime. APF integrates at two seams:

```
OpenShell
│
├── Gateway Interceptor  ◀────── apf-openshell-interceptor  (runs inside apf-policy-gateway)
│   [OpenShell control plane]     fetches SandboxPolicy projection once per sandbox
│   (sandbox admission)           injects as apf.nvidia.com/* annotations
│
└── Supervisor Middleware ◀────── apf-openshell-middleware   (runs inside apf-policy-gateway)
    [OpenShell data plane]        calls EvaluationService/Evaluate in-process
    (per-request egress)          enforces: allow/deny, body patches, header mutations
```

The two seams map onto different OpenShell planes. APF's own control/data distinction is orthogonal: APF's control plane is policy distribution (service → gateway); both OpenShell seams sit on APF's data plane since in both cases APF is serving a decision or a projection, not distributing policy.

**OpenShell owns:** sandbox lifecycle, network namespace, transport. APF does not dictate how sandboxes run.

**APF owns:** what policy applies, whether a request is permitted, what the response looks like.

The boundary is the `EvaluationService/Evaluate` RPC and the `SandboxPolicy` projection. A future runtime (e.g. another sandbox runtime) adds `crates/apf-<runtime>-*` adapter crates following the same pattern.

---

## 4. Sequence Diagrams

### 4.1 Control plane — bundle distribution and hot-swap

```
Policy Author          apf-policy-service        apf-policy-gateway
     │                        │                         │
     │  compile + publish      │                         │
     │───────────────────────▶│                         │
     │                        │ sign bundle              │
     │                        │ (BundleSigner/Ed25519)   │
     │                        │ store in PolicySource    │
     │                        │                         │
     │                        │◀── GetDocument (poll) ──│  digest_watcher
     │                        │                         │
     │                        │  digest unchanged?       │
     │                        │  ──── 304 / same ──────▶│  no-op
     │                        │                         │
     │                        │  digest changed:         │
     │                        │── GetDocumentResponse ──▶│
     │                        │  body + provenance_token │
     │                        │                         │
     │                        │                    verify_bundle()
     │                        │                    • BundleVerifier (sig)
     │                        │                    • manifest hashes
     │                        │                    • expiry
     │                        │                    • runtime_compatibility
     │                        │                    • monotonic counter
     │                        │                         │
     │                        │                    verify provenance_token JWT
     │                        │                    (JWKS-cached Ed25519 key)
     │                        │                         │
     │                        │                    build CedarEvaluator
     │                        │                    arc-swap (lock-free)
     │                        │                         │
     │                        │                    ✓ new bundle live
```

### 4.2 Data plane — sandbox admission (gateway interceptor, OpenShell control plane)

The `SandboxPolicy` bytes are compiled by `apf-openshell-projector` (running inside
`apf-policy-service`) from APF `CanonicalPolicy` IR. The interceptor decodes
pre-compiled bytes — no runtime lowering happens at admission time.

`apf-openshell-interceptor` runs as a gRPC server task **inside the
`apf-policy-gateway` process**; it is not a separate binary.

```
Agent          OpenShell Gateway    apf-openshell-interceptor   apf-policy-service
  │                   │             (inside apf-policy-gateway)        │
  │  spawn sandbox    │                    │                       │
  │──────────────────▶│                    │                       │
  │                   │── interceptor ────▶│                       │
  │                   │   hook fires        │                       │
  │                   │                    │── GetDocument ────────▶│
  │                   │                    │   (SandboxPolicy)      │
  │                   │                    │◀── body +              │
  │                   │                    │    provenance_token ───│
  │                   │                    │                       │
  │                   │                    │  verify provenance_token
  │                   │                    │  check digest, spec-digest
  │                   │                    │                       │
  │                   │                    │  inject annotations:
  │                   │                    │  apf.nvidia.com/policy-digest
  │                   │                    │  apf.nvidia.com/provenance-token
  │                   │                    │                       │
  │                   │◀── admit sandbox ──│                       │
  │◀── sandbox ready ─│                    │                       │
```

### 4.3 Data plane — per-request evaluation (supervisor middleware)

```
Agent        OpenShell Supervisor    apf-openshell-middleware    apf-policy-gateway
              Middleware              (inside apf-policy-gateway)      (PDP)
  │                │                       │                        │
  │  tool call /   │                       │                        │
  │  egress req ──▶│                       │                        │
  │                │── middleware hook ───▶│                        │
  │                │                       │── EvaluateHttpRequest ─▶│
  │                │                       │   (verb, resource,     │
  │                │                       │    args, context)      │
  │                │                       │                        │
  │                │                       │                  CedarEvaluator
  │                │                       │                  .evaluate(input)
  │                │                       │                        │
  │                │                       │◀── EvaluateResponse ───│
  │                │                       │    decision + obligations
  │                │                       │    body_patches
  │                │                       │    header_mutations
  │                │                       │    findings
  │                │                       │                        │
  │                │                       │  enforce:
  │                │                       │  DENY → reject request
  │                │                       │  ALLOW → apply patches/mutations
  │                │                       │                        │
  │                │◀── enforced response ─│                        │
  │◀── response ───│                        │                        │
```

---

## 5. Planned extensions

### 5.1 OpenShell response path hooks *(RFC 0009 protocol-extensions appendix)*

OpenShell RFC 0009 v1 defines one hook (`PRE_CREDENTIALS`, documented in §4.3). The
protocol-extensions appendix names two future response-path hooks. Neither is implemented
or scheduled; they exist to validate that v1's shape is forward-compatible.

**`HttpResponse/before_return`** — fires after the upstream responds, before the response
reaches the sandbox. Allows inspection **and mutation** (e.g. redaction of upstream
response content). This is the meaningful response hook for APF: content policy applied
on the return path, not just on the request path.

**`HttpResponse/completed`** — fires after the upstream request completes. Notification-only:
no body, no transformation, no allow/deny. Carries metadata: status, content length,
selected route/model, model token usage. Intended for budget-style reconciliation and
post-call audit.

**Full future sequence with all hooks:**

```
Agent        OpenShell Supervisor    apf-openshell-middleware    apf-policy-gateway
              Middleware              (inside apf-policy-gateway)
  │                │                       │                        │
  │  egress req ──▶│                       │                        │
  │                │  [PRE_CREDENTIALS]     │                        │
  │                │── hook fires ────────▶│── EvaluateHttpRequest ─▶│
  │                │                       │◀── decision + mutations─│
  │                │◀── enforced req ──────│   (allow/deny, patches, │
  │                │   (credentials        │    header mutations)    │
  │                │    injected after)    │                        │
  │                │                       │                        │
  │                │  (upstream call)      │                        │
  │                │                       │                        │
  │                │  [HttpResponse/before_return — planned]        │
  │                │── hook fires ────────▶│── EvaluateHttpRequest ─▶│
  │                │                       │◀── mutations ───────────│
  │                │◀── redacted response ─│   (response redaction,  │
  │                │                       │    header mutations)    │
  │                │                       │                        │
  │                │  [HttpResponse/completed — planned]            │
  │                │── notification ──────▶│                        │
  │                │                       │  status, token usage,   │
  │                │                       │  route/model → audit   │
  │◀── response ───│                       │                        │
```

**APF intended use:**

| Hook | APF use |
|---|---|
| `PRE_CREDENTIALS` (v1) | Allow/deny + request redaction + content inspection |
| `HttpResponse/before_return` (planned) | Response redaction; upstream content policy |
| `HttpResponse/completed` (planned) | Budget reconciliation; post-call audit with token usage |

### 5.2 `apf-cred-proxy` *(partially implemented — Spike 2 pending)*

**Role:** sits between the in-sandbox agent and upstream MCP servers (Slack, GitLab, Outlook, etc.). Three responsibilities:

1. **Credential swap** — looks up a vaulted OAuth token for the `(subject, service)` pair; the agent never sees raw tokens
2. **Policy consultation** — calls `apf-policy-gateway EvaluationService/Evaluate` per call; forwards only on ALLOW
3. **Audit capture** — emits audit events with full request context

Direct sandbox egress to corporate hosts is blocked at the network namespace; cred-proxy is the only permitted path out.

**Data plane position:**

```
Agent (in sandbox)
  │  MCP tool call to external service
  ▼
apf-cred-proxy  ──Evaluate──▶  apf-policy-gateway
  │                            (decision + obligations)
  │  ALLOW:
  │  look up vaulted token (CredentialStore)
  │  apply redaction obligations
  ▼
Upstream MCP server (Slack, GitLab, etc.)
```

**Current implementation state:**
- `CredentialStore` trait (`hosttool-vault`) — implemented. `LocalFileCredentialStore` (dev), Vault KV v2 (production target).
- `CredentialDocument`: versioned `BTreeMap<CredentialFieldName, Zeroizing<String>>` with CAS revision.
- Per-call MCP proxy layer (token swap + policy consultation in-line) — **deferred to Spike 2, not yet built.**

**Separation rationale:**
- Different trust profile — holds secrets; policy-gateway holds only policy data
- Different availability domain — credential outage ≠ deny-all egress decision
- Different lifecycle — credentials rotate independently of bundle updates

**Integration roadmap with OpenShell:**

| Phase | Mechanism | OpenShell changes |
|---|---|---|
| Short-term (v0) | `apf-tool-gateway` calls `apf-cred-proxy` directly before tool invoke | None |
| Medium-term | Declare `apf-cred-proxy` as `token_grant` endpoint in provider profile YAML; OpenShell's existing flow calls it at sandbox create | None |
| Long-term | gRPC `ProviderPlugin` interface — `apf-cred-proxy` registers as a named credential source at runtime | OpenShell RFC required |

**Future interface:** `CredentialBackend` trait in `crates/apf-types`. Tool-gateway will call cred-proxy over a local contract for credential injection on the hosttool path too.


---

## 6. Control plane vs data plane summary

| | Control plane | Data plane |
|---|---|---|
| **What flows** | Policy bundles and projections | Agent requests and decisions |
| **Initiator** | Policy author → service; service → gateway (poll) | Agent → OpenShell → gateway |
| **Latency tolerance** | Seconds to minutes (background) | Sub-millisecond (hot path) |
| **Cloud dependency** | Required (service is the PAP) | None after bundle loaded |
| **APF components** | `apf-policy-service`, `apf-policy-gateway` (fetch/verify) | `apf-policy-gateway` (evaluate), `apf-openshell-interceptor`, `apf-openshell-middleware` |
| **Failure mode** | Gateway holds last known good bundle | Deny-safe: gateway denies if evaluator unavailable |

---

## 7. Deployment Models

### 7.1 Co-located (current supported model)

`apf-policy-service` and `apf-policy-gateway` run on the same host. The service compiles, signs, and serves bundles over a Unix domain socket; the gateway fetches from it locally. No network hop on the control plane.

```
  ┌─────────────────────────────── Host ────────────────────────────────┐
  │                                                                     │
  │  apf-policy-service (PAP)         apf-policy-gateway               │
  │  • compile / sign / serve  ◀── GetDocument (UDS poll) ──           │
  │  • PolicyService gRPC (UDS)                                         │
  │  • LocalBundleSource or HttpBundleSource                            │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

The service–gateway transport is a Unix domain socket. The bundle source (`LocalBundleSource` or `HttpBundleSource`) is independent of the transport and can be configured without changing the co-located topology.

### 7.2 Cloud-based PAP *(planned)*

`apf-policy-service` runs in a shared cloud environment (e.g. Kubernetes). Gateway instances on multiple hosts fetch bundles from a single PAP over the network. Bundle storage is backed by Artifactory (`HttpBundleSource`).

```
  Cloud ──────────────────────────────────────────────────────────────────────
  │  apf-policy-service (PAP)                                              │
  │  • compile / sign / serve bundles                                      │
  │  • PolicyService gRPC + HTTP (mTLS)                                    │
  │  • HttpBundleSource — pulls signed bundles from Artifactory            │
  └────────────────────────────────────────────────────────────────────────
                │
                │  GetDocument  (mTLS / TCP)
                ▼
  Host A ─────────────────────────────────────────────────────────────────────
  │  apf-policy-gateway                                                    │
  │  • verify + evaluate locally — no cloud dependency on hot path         │
  └────────────────────────────────────────────────────────────────────────
  Host B ─────────────────────────────────────────────────────────────────────
  │  apf-policy-gateway                                                    │
  └────────────────────────────────────────────────────────────────────────
```

No gateway code changes required. The gateway client is transport-agnostic; switching from co-located to cloud-based PAP is a configuration change only.

For the policy bundle lifecycle — CI compilation and signing, Artifactory distribution, and the end-to-end flow from author commit to live policy — see [docs/policy-publishing.md](policy-publishing.md).
```
