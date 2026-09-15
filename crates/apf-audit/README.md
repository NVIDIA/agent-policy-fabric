<!-- SPDX-License-Identifier: Apache-2.0 -->
# APF Audit — event reference

`apf-audit` is the shared library every APF component emits audit records
through. This document explains **what each audit event type means, which
component produces it, and when it fires.**

The authoritative contract is the JSON Schema `apf.audit.event.v1`
(`../../contracts/audit/apf.audit.event.v1.schema.json`). Every record validates
against it before it is written. Where this prose and the schema disagree, the
schema wins.

---

## The model in one picture

APF is a policy fabric with several enforcement points. Signed policy is
authored and signed **offline** (`apf-compile`); it is not created here.

```
apf-compile               (offline)  → authors & SIGNS bundles
apf-policy-service        (PAP)      → verifies, projects, stores & SERVES bundles
apf-policy-gateway        (PDP)      → the local decision point
apf-openshell-interceptor (adapter)  → sandbox admission
apf-openshell-middleware  (adapter)  → per-request egress
apf-openshell-auth        (adapter)  → the extension trust boundary
```

`apf-policy-service` **never authors, signs, or evaluates.** It verifies a
signed bundle (from a local path or an HTTP source), compiles it to
projections, and serves them to the gateway over gRPC (`--socket`) or HTTP
(`--http-addr`, `GET /v1/documents/{kind}/{name}`).

One JSONL file per component:

```
apf-policy-service-audit.jsonl
apf-policy-gateway-audit.jsonl
apf-policy-gateway-interceptor-audit.jsonl
apf-policy-gateway-middleware-audit.jsonl
```

---

## The type names the operation; a separate field says how it went

Each `event_type` names the operation or fact the record is about —
`authorization`, `policy_activation`, `policy_injection`. How it turned out
lives in a separate field:

- **`outcome`** — `success`, `failure` (an operational error), or `refused` (a
  deliberate rejection). Carried by every operation event.
- **`decision`** — `allow` / `deny` / … — the policy verdict on a request.
  Carried by **`authorization` only**; no other type evaluates a request.

Reading the type tells you *what happened*; reading `outcome` (or, for an
authorization, `decision`) tells you *how it went*.

---

## Event types

The schema defines **14** event types. **11 have producers today; 3 are
reserved** (human review and credential issuance, kept so the vocabulary stays
stable if those capabilities ship).

### Active event types

| `event_type` | Meaning | Emitted by | When |
|---|---|---|---|
| `policy_service_startup` | The **security state of the config the service started with** (`security_state`: `secure` / `degraded` / `rejected`), and which protection was weakened if any. | **policy-service only** | Once at startup. Records the state at that moment; it does **not** prove continued enforcement or that every later request was logged. |
| `policy_verification` | A bundle was **verified** (signature, counter, projections). `outcome: refused` with `rejection_reasons[]` when a check fails; `outcome: failure` on an operational error. | policy-service | On every verify, before activation. |
| `policy_activation` | A verified bundle was **brought into force** (initial load or live hot-swap). The stage is in `reason_code`: `bundle_loaded`, `bundle_hot_swapped`. | policy-service, policy-gateway | When a bundle becomes active. |
| `policy_distribution` | A projected policy **document was served** to a consumer. | policy-service | Per document vend. See [Distribution records](#distribution-records-and-their-limits) for what this does and does not prove. |
| `policy_refresh` | An operator **refresh of the served policy** was requested or completed. | policy-service | On an operator-triggered refresh. Split out from distribution because it is an operator action, not a delivery. |
| `provenance_signing` | A served document's **provenance record was signed** — or, when signing failed, that the document was **served unsigned** (`served_unsigned: true`). | policy-service | Per served document that carries provenance. A `refused`/`failure` here does **not** always mean "not served." |
| `authorization` | A governed action was **evaluated by policy**. Carries `decision` (`allow`/`deny`), and any `findings`, `verdict`, `effects`. This is the **only** decision event. | policy-gateway, middleware | Per governed request/egress. A middleware egress block is an `authorization` with `decision: deny`. |
| `policy_injection` | The interceptor **rewrote a sandbox-admission manifest** to enforce policy. The mutation *is* the operation; the applied patches are in `effects`. | interceptor | Per admission that injects policy (OpenShell `MODIFY_OPERATION`). |
| `admission_validation` | The interceptor **validated a sandbox-admission manifest** against policy. The checks run and skipped are in `checks`. | interceptor | Per admission validation (OpenShell `VALIDATE`). |
| `config_governance` | The interceptor **admitted or refused a configuration change**. | interceptor | Per governed config apply. |
| `authentication` | A caller was **authenticated at the trust boundary** — `outcome: refused` on a bad credential, an unauthenticated caller, a disallowed caller kind, or a sandbox-binding mismatch. Carries no policy or subject identity: none is established when authentication fails. | interceptor, middleware, openshell-auth, policy-service | At the extension trust boundary, before policy is consulted. |

### Reserved types (no producer today)

Retained so the vocabulary stays stable if these capabilities ship:

| `event_type` | Status |
|---|---|
| `review_request` | Reserved — no human-review gate yet. Would record that a request was routed to review. |
| `review_decision` | Reserved — the outcome of that review. Carries `decision`. |
| `credential_issuance` | Reserved — no component issues credentials. `outcome: success` for an issued credential, `refused` for a denied request. |

---

## `event_type`, `decision`, and `verdict`

Distinct and orthogonal. An `authorization` record may carry all three.

| Field | Values | Answers | Absent means |
|---|---|---|---|
| `event_type` | the 14 above | The **shape** of the record. | n/a (always present) |
| `decision` | `allow`, `deny`, `require_review`, `require_step_up`, `quarantine`, `stop_session` | The policy **verdict** on a request. *(OpenShell seams emit only `allow`/`deny` today.)* On `authorization`, and on the reserved `review_decision` (a reviewer's verdict). | Not a decision event, so no verdict. |
| `verdict` | `allow`, `warn`, `escalate` | The engine's **advisory signal**. | **No advisory verdict was recorded — use `decision` for the outcome.** Omitted on plain allows *and* on denies; absence is not "allowed." |

Note `outcome` is a fourth, distinct field: it reports how a **non-decision
operation** went, and never appears on an `authorization` (which uses
`decision`).

---

## `findings` vs `effects` — observed vs done

- **`findings[]`** — what policy **observed** (e.g. `secret_detected / openai_key / critical`). Never changes the decision. Present on allows and denies alike, on the **`authorization`** event only.
  - `minItems` 1, `maxItems` 32 — the array is **omitted entirely when empty**, never emitted as `[]`.
  - Required per entry: `kind`, `label`, `severity`. Optional: `confidence` (0–100).
  - **Not deduplicated** — the effect engine pushes one entry per firing; order mirrors bundle-manifest then policy order.
- **`effects{}`** — what policy **did** to a request in flight: `patch_count`/`patches` (path + op, never the value). Permitted on exactly the two types that mutate: an **`authorization`** (a redaction that enforced an allow) and a **`policy_injection`** (the interceptor rewriting an admission manifest). Omitted when nothing was applied.

An authorization redaction record carries **both**: the finding (a secret was
seen) and the effect (the body was patched) — proving the request was
*allowed, flagged, and neutralised* rather than let through untouched.

---

## Distribution records and their limits

`policy_distribution` fires when policy-service serves a projected document.
Read it as *"this policy version was distributed at least once"* — **not** as a
per-consumer delivery receipt.

**A distribution record proves:** a document of `(kind, name)` at a given
`(digest, version)` was served.

**It does not prove *who* received it, or *how many* times:**

- **No caller identity.** The service serves the gateway, not a user or
  session. The schema leaves the subject fields optional, but policy-service
  does not populate them — the record says *that* a document was served, not
  *to whom*.
- **Deduplicated per document, not per consumer.** Emission is suppressed by
  `(kind, name)` + `(digest, version)`. Once one consumer has fetched a
  document at a given digest/version, a *different* consumer fetching the same
  document may produce **no new record**.
- **Refreshes are separate.** An operator refresh is a `policy_refresh` event,
  not a `policy_distribution`.

---

## Emission guarantees — per path, not global

There are two disciplines, and **the choice is per event, not per component**:

- **Fail-closed** (`emit_required`) — if the record cannot be written, the
  operation fails. Used where an unrecorded outcome would be unsafe, e.g. the
  initial bundle verification / activation.
- **Best-effort** (`emit_best_effort`) — a failed write logs and continues.
  Used per-request, **and for some lifecycle events**: hot-swap acceptance and
  rejection, `no_projections`, and the serving-surface events are best-effort.
  A failed hot-swap audit may require **rollback of the swap**, not process
  shutdown.

So "lifecycle = fail-closed, per-request = best-effort" is **not** a rule.
Check the specific emit method. A record can also be written in a **degraded**
form (see next section) rather than lost.

---

## Sanitization and fallback

Every string in a serialized event is scanned by `SanitizationGuard` before it
is written; caller-controlled fields are also length-capped and coerced. When a
value would fail validation or trips the guard, the producer **degrades the
record rather than dropping it**: the decision/outcome, policy identity, and
event type are preserved, while the offending caller-supplied fields are
replaced with sentinels and a `reason` marker records that degradation
occurred.

Consequence for consumers: a record always tells you *what was decided*, but a
degraded record may have `unspecified`/`unrecordable` in detail fields and a
`reason` like `"caller-supplied … omitted"`. Do not treat those sentinels as
real identities.

---

## When each seam evaluates — the request lifecycle

```
1. STARTUP
   policy-service: policy_service_startup (security_state: secure → startup.secure)
                   policy_verification  (outcome: success → bundle_verified)
                   policy_activation    (outcome: success → bundle_loaded)
   policy-gateway: policy_activation    (reason_code: bundle_activated)

2. SANDBOX ADMISSION            (interceptor)
   MODIFY_OPERATION → policy_injection     (outcome: success | refused)
   VALIDATE         → admission_validation (outcome: success | refused)
   config change    → config_governance    (outcome: success | refused)

3. EACH GOVERNED REQUEST        (middleware)
   extension auth → authentication (outcome: refused on a boundary failure)
   evaluate       → authorization  (decision: allow | deny)
                    (+ findings observed, + effects applied)

4. POLICY DISTRIBUTION          (policy-service, continuous)
   policy_distribution   when a document is served
   provenance_signing    per served document that carries provenance
   policy_refresh        on an operator refresh
```

---

## How findings are populated

A finding is an *observation behind an action*. The common demo pattern uses
four documents, but **not all four are required** — findings can be defined
inline on a rule, and an effect can emit a finding without modifying content.

| Document | Role | Required? |
|---|---|---|
| `PolicyAnnotator` | Detects — sets annotations (e.g. `secret_detected`, `secret_kind`). | Only if you key on a detection. |
| `PolicyFinding` | Named finding template — YAML `type` → audit **`kind`**, plus `severity`, `label`/`label_source`. | Only for *named* findings; a rule/effect may declare an **inline** finding instead. |
| `PolicyRule` | Cedar logic that decides; may reference a finding (`@apf_finding`, on `forbid` **or** `permit`). | Yes. |
| `PolicyEffect` | A mutation that may also reference a finding — including an effect that emits a finding without changing the body. | Only when mutating or attaching a finding to an allow. |

**At runtime:**

```
R1 Detect   annotator sets annotations (if used)
R2 Decide   Cedar fires a rule → decision (allow/deny)
R3 Attach   the fired construct references a finding — by name or inline
R4 Resolve  the finding fills in kind (from YAML `type`), severity, label
R5 Record   the adapter writes findings[] (+ effects{}) on the authorization,
            omitting an empty array
```

**Where the reference lives (R3)** — the finding is *referenced*, never
*contained*; a named `PolicyFinding` is a separate document:

| | On the decision | On the mutation |
|---|---|---|
| Written as | `@apf_finding("…")` on a `forbid` or `permit` rule | `finding: …` in a `PolicyEffect` |
| Typical use | "we blocked/allowed it, here's why" | "we rewrote it, here's why" |

See `apf-policy-eval/src/cedar/effect.rs` (`resolve_finding`, and the
`CompiledFindingRef::{Named, Inline}` variants) for how both forms resolve.

---

## Correlation and cross-component joins

Records are joined across seams by `correlation_id` — but only when the same id
is **propagated** through the call chain. A component that generates a fresh id
(or receives none) cannot be joined to upstream events on it. In the demo, the
synthetic grpcurl acts hardcode `correlation_id: "demo"`; only requests that
flow through a real OpenShell supervisor carry a genuine propagated id. Do not
assume every record with related timing shares a correlation id.

---

## Reason codes (selected — not exhaustive)

`reason_code` is the machine-readable sub-type within an event. These are
**representative**, not a complete list; grep the source for the authoritative
set.

**policy-service:** `startup.secure`, `startup.insecure_transport_enabled`,
`startup.provenance_verification_disabled`, `startup.bundle_source_unauthenticated`,
`policy.bundle_verified`, `policy.bundle_loaded`,
`policy.bundle_hot_swapped[.counter_not_persisted]`,
`policy.bundle_rejected.{verification_failed,counter_not_newer,counter_persist_failed}`,
`policy.document_vended`, `policy.document_not_found`, `policy.no_projections`,
`policy.refresh_triggered`, `provenance.record_signed`,
`provenance.mint_failed`.

**policy-gateway:** `policy.bundle_activated`, `policy.bundle_hot_swapped`,
`policy.request_allowed`, `policy.request_denied`.

**interceptor:** `admission.policy_injected[.unverified]`,
`admission.manifest_validated[.no_spec_digest]`, `admission.inject_denied.*`,
`admission.validate_denied.*`, `config.change_admitted`, `config.govern_denied.*`.

**middleware:** `middleware.allowed[_with_findings]`, `middleware.policy_denied`,
`middleware.evaluation_failed`, `substrate.egress_denied`, `extension_auth.*`.

**openshell-auth:** `extension_auth.credential_invalid`,
`extension_auth.caller_unauthenticated`, `extension_auth.caller_not_allowed`,
`extension_auth.sandbox_binding_mismatch`.

---

## Shipping records downstream

Each component writes JSONL to its `--audit-log-dir`. A Fluent Bit tail with a
wildcard picks up all files and can forward them to a SIEM such as
Splunk. Query on `component.name` and `enforcement_point_id`
(producer-written) rather than filename (shipper-inferred).
