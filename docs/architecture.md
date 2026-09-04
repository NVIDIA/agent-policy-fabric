# APF Architecture

---

## Enterprise-governed policy for agentic flows

APF governs a workload across its full lifecycle: sandbox admission (what is allowed to
run) and per-request evaluation (whether an already-admitted call, given its arguments and
target, actually holds up). Both decisions come from the same signed policy; the runtime
carries them out.

Authoring, administration, and enforcement are held by separate parties. Enterprise teams
author and sign policy offline, through the enterprise policy-authoring and publish path —
APF supplies the compile and signing mechanics, not a new workflow. 
The policy service verifies the signed bundle, projects it for the target runtime,
and serves it; it does not author policy today, and is the natural home for authoring
mechanics as it evolves ([policy-publishing.md §4](policy-publishing.md)). The policy gateway
evaluates against the signed bundle and the runtime hooks hand its decisions to the runtime,
which enforces them; none of them can author or modify the bundle.

- **Policy as code** — policy is a set of versioned documents, not configuration on a host.
  - *Reviewed* — every change is a document diff with a reviewer.
  - *Federated* — Security, Compliance, and tool owners each contribute their own documents
    to one signed bundle without touching a shared codebase.
  - *Propagated* — a published bundle reaches every policy gateway that serves it, with no
    restart or software deploy; every host runs the same version
    ([policy-publishing.md](policy-publishing.md)).
  - *Traceable* — every sandbox carries the identity of the bundle it was admitted under.
- **Verified before it is served** — the policy service checks a bundle's signature,
  integrity, expiry, and runtime compatibility once at ingest, and rejects any version older
  than one already accepted, so a superseded policy cannot be reintroduced.

---

## 1. Components

| Component | Role | Plane |
|---|---|---|
| `apf-policy-service` | **Policy Administration Point.** Verifies signed bundles, projects them for the target runtime, stores and serves them. Never evaluates requests. | Control |
| `apf-policy-gateway` | **Host-side policy agent.** Embeds the local Policy Decision Point — fetches bundles, evaluates every request in-process with no cloud dependency on the hot path — and hosts the runtime adapters. | Control (fetch) + Data (evaluate) |
| `apf-openshell-projector` | Adapter in the policy service. Lowers APF policy into OpenShell-native projections at bundle load. | Control |
| `apf-openshell-interceptor` | Adapter in the policy gateway. At sandbox admission, delivers the projection to OpenShell and stamps provenance. | Data |
| `apf-openshell-middleware` | Adapter in the policy gateway. On each egress request, returns APF's decision for OpenShell to enforce. | Data |
| `apf-compile` | Authoring-side CLI. The enterprise policy-authoring + publish path runs it to compile and sign a bundle offline. | Offline |

Adapters are the only place runtime-specific types appear. Adding a second sandbox runtime
means adding a new set of `apf-<runtime>-*` adapters; shared libraries and services are
unchanged.

Tool invocation and credential procurement belong to the network egress gateway, not
in this workspace. It consults the policy gateway for a decision before each tool call.

---

## 2. Component Diagram

```
  Enterprise authoring + publish ── signed bundle ──▶  apf-policy-service (PAP)
  (apf-compile)                                        verify · project · serve
                                                                 │
                                                                 │  fetch (poll)
                                                                 ▼
                                                        apf-policy-gateway
                                                        local PDP — evaluates in-process
                                                 ┌───────────────┴───────────────┐
                                                 │ decision                      │ projection
                                                 ▼                               ▼
                                     apf-openshell-middleware        apf-openshell-interceptor
                                     per-request                     sandbox admission
                                     (inside gateway process)        (inside gateway process)
                                                 │                               │
                                                 └───────────────┬───────────────┘
                                                                 ▼
                                                 OpenShell enforces: blocks or edits the request,
                                                 applies containment to the sandbox
```

---

## 3. Positioning within OpenShell

APF applies sandbox policy wherever agents run; OpenShell is the sandbox runtime it is
integrated with today. APF integrates at two seams:

```text
OpenShell
│
├── Gateway Interceptor    ◀──  apf-openshell-interceptor   sandbox admission:
│                                                           delivers projection, stamps provenance
│
└── Supervisor Middleware  ◀──  apf-openshell-middleware    per-request:
                                                            returns allow / deny / obligations
```

**OpenShell owns:** sandbox lifecycle, network namespace, hook registration, trusted service
CAs, and authenticating itself to APF's hooks. APF does not dictate how sandboxes run.

**APF owns:** what policy applies, whether a request is permitted, what mutations apply, and
the trust anchor it uses to authenticate OpenShell as a caller.

The boundary is the policy decision and the sandbox-policy projection. Hook authentication,
trust-profile provisioning, and insecure mode are documented in
[`deploy/systemd/SECURITY.md`](../deploy/systemd/SECURITY.md).

---

## 4. Control plane vs data plane

| | Control plane | Data plane |
|---|---|---|
| **What flows** | Policy bundles and projections | Agent requests and decisions |
| **Initiator** | Enterprise policy-authoring + publish path → service; gateway polls service | Agent → OpenShell → gateway |
| **Latency tolerance** | Seconds to minutes (background) | Sub-millisecond (hot path) |
| **Cloud dependency** | Required (service is the PAP) | None after bundle loaded |
| **Failure mode** | Gateway keeps the last known good bundle | Deny-safe: an evaluation error is a deny |

APF's control/data split is orthogonal to OpenShell's: both OpenShell seams sit on APF's data
plane, since in both cases APF is serving a decision or a projection, not distributing policy.

---

## 5. Deployment Models

### 5.1 Co-located (current supported model)

`apf-policy-service` and `apf-policy-gateway` run on the same host. The service verifies,
projects, and serves bundles over a local socket; the gateway fetches from it locally. No
network hop on the control plane. The bundle source (local directory or remote registry) is
independent of the topology.

```
  ┌───────────────────────────────── Host ──────────────────────────────────┐
  │                                                                         │
  │  apf-policy-service   ◀── fetch (local socket) ──   apf-policy-gateway  │
  │  verify · project · serve                           evaluate locally    │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Cloud-based PAP *(planned)*

`apf-policy-service` runs in a shared cloud environment. Gateway instances on multiple hosts
fetch bundles from a single PAP over the network. The gateway is transport-agnostic; moving
from co-located to cloud-based PAP is a configuration change, not a code change.

```
  Cloud
  │  apf-policy-service (PAP) — verify · project · serve
  └──────────────┬────────────────────────────────────────
                 │  fetch (mTLS)
       ┌─────────┴─────────┐
       ▼                   ▼
  Host A                Host B
  apf-policy-gateway    apf-policy-gateway
  evaluates locally     evaluates locally
```

---

## Detailed flows

- [policy-publishing.md](policy-publishing.md) — compile, sign, publish, distribute, hot-swap
- [governed-path.md](governed-path.md) — admission and the per-action enforcement layers: where APF decides and where the runtime enforces
- [policy-model.md](policy-model.md) — document kinds, evaluation pipeline, bundle format
