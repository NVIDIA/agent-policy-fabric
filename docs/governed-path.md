# Governed Path

An agent gets one path to the outside world, and it is the same path every time.

Before the agent runs, its sandbox is set up from a policy Security signed off on: which hosts
it can reach, what it can touch on disk, what it can execute. That happens once, when the
sandbox is created. From then on, every single thing the agent tries to do — post a Slack
message, open a pull request, call an API — has to clear a series of checks before it
actually happens. Fail one check and the action stops right there.

The rules themselves come from the enterprise. Security and Compliance teams author the
curated policy that says which tools and resources agents may reach, and under what
conditions. Authoring and signing happen offline, through the enterprise policy-authoring and publish path — not
inside a running APF component. APF supplies the mechanics for that step: the compiler
(`apf-compile`), the bundle format, and the signature scheme.

From there APF takes over. The policy service checks the signed bundle — signature, integrity,
and that it is compatible with the runtime it is meant for — and projects the policy onto the
approved runtime. At call time APF's gateway makes the decision on each action. The runtime
does the physical work: it builds the walls around the agent from the projection, and when the
gateway says "deny" or "strip this field out first", the runtime is what actually blocks or
edits the request.


| Step                               | Enterprise teams                     | APF                                                                 | Runtime                                                            |
| ---------------------------------- | ------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Author + sign policy               | Author, review, sign (offline)       | Provides `apf-compile`, bundle format, signature scheme             | —                                                                  |
| Verify + serve                     | —                                    | `apf-policy-service` verifies signature, integrity, runtime compatibility; serves projections | —                                        |
| Admission                          | —                                    | Projects `SandboxPolicy`, stamps provenance onto the sandbox        | Applies the projection: network, filesystem, process               |
| Layer 1 — containment + capability | —                                    | — (configured from APF's projection)                                | Enforces per call: reachable destinations, permitted tools/methods |
| Layer 2 — content + context        | —                                    | `apf-policy-gateway` evaluates and returns a decision + obligations | Rejects the call or applies the returned patches/mutations         |


For component roles and the control/data plane split, see [architecture.md](architecture.md).
For how the signed bundle reaches the gateway, see [policy-publishing.md](policy-publishing.md).

---



## 1. Admission

Admission is the one-time gate at sandbox creation. It decides what a sandbox is allowed to
run as and pins the exact policy version it was admitted under, so every later decision on
this path can be traced back to it.

The `SandboxPolicy` projection is compiled ahead of time inside `apf-policy-service` from APF
`CanonicalPolicy` IR. APF's admission hook fetches those pre-compiled bytes and hands them to
the runtime — no policy lowering happens at admission time, and the hook holds no authoring
capability. If the projection cannot be fetched or fails verification, admission fails closed.

APF also stamps provenance onto the sandbox: the policy document digest and the provenance
token minted by `apf-policy-service`. These identify which signed policy governs the sandbox.

Admission is split across two hook invocations. The create/modify phase fetches the projection
and injects it; a later, separate validate phase reads the provenance token back and verifies
it before the runtime admits the sandbox.

```
Agent              Runtime gateway             APF admission hook              apf-policy-service
                                           (inside apf-policy-gateway)
  │                       │                             │                               │
  │ spawn sandbox         │                             │                               │
  │──────────────────────▶│                             │                               │
  │                       │──── HTTPS + Bearer JWT ────▶│                               │
  │                       │ [create / modify]  verify caller                            │
  │                       │                             │─ GetDocument (SandboxPolicy) ▶│
  │                       │                             │◀── body + provenance_token ───│
  │                       │                             │                               │
  │                       │                             │ APF projects:                 │
  │                       │                             │ inject SandboxPolicy + annotations
  │                       │                             │ apf.nvidia.com/document-digest
  │                       │                             │ apf.nvidia.com/provenance-token
  │                       │                             │                               │
  │                       │◀────── sandbox spec ────────│                               │
  │                       │                             │                               │
  │                       │──── HTTPS + Bearer JWT ────▶│                               │
  │                       │ [validate]  APF verifies:   │                               │
  │                       │                             │ provenance JWT + digest       │
  │                       │                             │ from the injected annotations │
  │                       │                             │                               │
  │                       │◀────────── admit ───────────│                               │
  │                       │ Runtime enforces: apply containment from projection         │
  │◀─── sandbox ready ────│                             │                               │
```



## 2. Per-action layers

Once admitted, every action travels the same layers. Each layer is a distinct check, run by a
distinct component, against a distinct input:

- **Layer 1** runs inside the sandbox runtime, against the `SandboxPolicy` projection fixed
  at admission — `spec.network_policies`, `spec.filesystem`, `spec.landlock`, `spec.process`,
  plus the provider profiles that name which tools and methods are reachable. It sees the
  destination and the tool/method identity, not the payload. No policy evaluation happens
  here; it is a lookup against configuration already on the host.
- **Layer 2** runs inside `apf-policy-gateway`. It receives the full request through the
  runtime's request hook, builds an `EvalInput` (tool, capability, authenticated subject,
  args, body, target), and runs the three-stage evaluator from the currently hot-swapped
  bundle — Annotator → Cedar → Effect (see [policy-model.md](policy-model.md)) — returning a
  decision plus obligations.

The order follows cost and specificity. Layer 1 is a static lookup that rejects
out-of-policy traffic before any body is parsed; Layer 2 parses the body and runs Cedar. A
call reaches Layer 2 only if Layer 1 allowed it. Adding a layer means adding a hook point
with its own input, and a subsection here describing it.

### Layer 1 — Containment and capability (runtime enforces)

Enforced by the sandbox runtime from the projection APF delivered at admission. Containment
restricts what the sandbox can even attempt: reachable network destinations, filesystem,
processes. Capability restricts which tools, methods, and resources the sandbox may reach at
all, decided from tool identity and method — not from what is inside the call.

APF does not sit on this layer at call time. Its contribution is the projection.

### Layer 2 — Content and context (APF decides, runtime enforces)

`apf-policy-gateway` evaluates an already-permitted call against its actual arguments, body,
target, and authenticated subject: does this call, with this content, hold up? The result is
a decision — allow, deny, or allow with obligations (body patches, header mutations,
findings). The runtime's request hook carries that decision out: it rejects the call or
applies the patches before the request leaves.

Evaluation input per call (`EvalInput`): tool name, capability, authenticated subject, call
arguments, request body (text and parsed JSON), and HTTP target. Each call is evaluated on its
own.

```text
Agent       Runtime request hook            APF request hook
                                       (inside apf-policy-gateway)
  │                   │                             │
  │ tool call /       │                             │
  │─── egress req ───▶│                             │
  │                   │                             │
  │                   │ Layer 1 — runtime enforces  │
  │                   │ containment + capability    │
  │                   │ deny ⊥ — stops here         │
  │                   │                             │
  │                   │──── HTTPS + Bearer JWT ────▶│
  │                   │                             │ verify caller + bind sandbox identity
  │                   │                             │
  │                   │                             │ Layer 2 — APF decides
  │                   │                             │ evaluator.evaluate(input)
  │                   │                             │ (in-process; evaluator from the hot-swap channel)
  │                   │                             │
  │                   │◀─ decision + obligations ───│
  │                   │                             │ allow / deny; body_patches,
  │                   │                             │ header_mutations, findings
  │                   │                             │
  │                   │ Runtime enforces:           │
  │                   │ DENY  → reject              │
  │                   │ ALLOW → apply patches / mutations
  │                   │                             │
  │ (upstream call)   │                             │
  │◀─── response ─────│                             │
```

The Layer 2 evaluate step is an in-process Rust call on the `Arc<dyn Evaluator>` obtained
from the gateway's hot-swap channel. It is not a second network hop: APF's request hook and
the policy gateway share one process.

## 3. OpenShell integration

OpenShell is the sandbox runtime APF is integrated with today. Both of APF's hooks are
adapter crates linked into the `apf-policy-gateway` binary — neither is a separate process —
and they share the gateway's policy client, trust roots, and hot-swapped evaluator.


| Path step | OpenShell surface                             | APF adapter                                          |
| --------- | --------------------------------------------- | ---------------------------------------------------- |
| Admission | Gateway interceptor                           | `apf-openshell-interceptor`                          |
| Layer 1   | Sandbox policy + provider-profile admission   | — (configured from APF's `SandboxPolicy` projection) |
| Layer 2   | Supervisor middleware, `PRE_CREDENTIALS` hook | `apf-openshell-middleware`                           |


Three facts about this integration shape the path:

- **Who may call each hook.** OpenShell authenticates itself to both hooks with a short-lived
  extension JWT. The admission hook accepts only the OpenShell gateway; the Layer 2 hook
  accepts only the supervisor, and binds each request to the sandbox identity in that token.
  Hook authentication, trust-profile provisioning, and insecure mode are covered in
  [`deploy/systemd/SECURITY.md`](../deploy/systemd/SECURITY.md).
- **Running sandboxes refresh through the runtime.** A new bundle reaches per-request
  evaluation immediately via hot-swap. The containment projection is re-fetched and
  re-injected only when OpenShell issues a config update for that sandbox; APF does not push
  a new projection into a running sandbox on its own.
- **Layer 2 never sees credentials.** The `PRE_CREDENTIALS` hook fires after OpenShell's own
  Layer 1 admission and before OpenShell injects provider credentials, so APF evaluates a
  credential-redacted view of every request.