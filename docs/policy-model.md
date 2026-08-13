# APF Policy Model

For how policy bundles move through CI, signing, and Artifactory distribution to a live gateway, see [policy-publishing.md](policy-publishing.md).

APF's policy model is built around semantic enforcement of agent behavior. The goal is not just access control — it is the ability to express, in auditable, team-authored policy, exactly what an agent may do, what content is permitted to flow through it, and what happens when a violation or signal is detected. Cedar is the decision language at the center of this model: its deliberate constraints (no recursion, no side effects, no I/O) make policies auditable by non-specialists and formally verifiable.

Cedar alone, however, cannot express detection logic (regex, length checks, numeric coercion) or mutation logic (body redaction, header injection). APF addresses this with a three-stage engine: a pre-Cedar annotator layer handles detection and injects structured signals into Cedar's context; Cedar conditions express the authorization decision against those signals; a post-Cedar effect layer applies mutations and emits audit findings. Each stage has its own schema and its own owners — security, compliance, and product teams contribute independent YAML documents without touching the engine or each other's artifacts.

A policy bundle is a signed collection of these YAML documents. The gateway loads the bundle once and evaluates every request locally against it — no cloud round-trip on the request path.

---

## Evaluation pipeline

The pipeline is the mental model for authoring: detection happens before the decision, enforcement happens after it. Every request passes through three stages in sequence, and each stage has a single concern.

```
  Incoming request
  │
  │  normalize → identity, tool/capability, arguments, body
  ▼
┌─────────────────────────────────────────────────────────────┐
│  Stage 1 — AnnotatorEngine                                  │
│                                                             │
│  PolicyAnnotator documents run in parallel                  │
│  Each inspects request content and sets a named value       │
│                                                             │
│  Output: context.annotations.*                              │
│  (available to all Cedar rules in Stage 2)                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Stage 2 — Cedar Evaluator                                  │
│                                                             │
│  PolicyRule documents evaluated in manifest order           │
│  against (principal, action, resource, context)             │
│                                                             │
│  First forbid → immediate deny, evaluation stops            │
│  Permits accumulate @apf_effect and @apf_finding refs       │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
           DENY                      ALLOW
              │                         │
              ▼                         ▼
        findings emitted     ┌─────────────────────────────────┐
        (if any on forbid)   │  Stage 3 — EffectEngine         │
        decision returned    │                                  │
                             │  Resolves @apf_effect refs       │
                             │  Applies body patches/mutations  │
                             │  Collects header mutations       │
                             │  Emits findings                  │
                             └──────────────┬──────────────────┘
                                            │
                                            ▼
                                   decision + mutations
                                   + findings returned
```

`SandboxPolicy` is evaluated once at sandbox admission — it is not part of the per-request pipeline.

## Policy kinds at a glance

Each stage of the pipeline is fed by its own document kind, plus two kinds outside the per-request path:

| Kind | Concern | When it runs | Typical owner |
|---|---|---|---|
| `SandboxPolicy` | Perimeter — network, filesystem, process | Once, at sandbox admission | Platform / security |
| `PolicyAnnotator` | Detection — extract signals from content | Stage 1, every request | Security / compliance |
| `PolicyRule` | Decision — permit or forbid (Cedar) | Stage 2, every request | Tool owners + platform |
| `PolicyEffect` | Enforcement — mutate, redact, escalate | Stage 3, on fired permits | Security / compliance |
| `PolicyFinding` | Observability — audit signal | Alongside any decision | Security / compliance |

Two details worth internalizing early:

- `PolicyRule` has two roles: `capability` rules grant access to specific tools (who may do what, contributed by tool owners); `control` rules enforce content policy across all traffic (what content is permitted, owned by platform or security teams).
- Annotators, effects, and findings are shared infrastructure — written once, referenced by name from any rule in the bundle. This is what lets teams contribute independently: the security team's `secret-detector` is available to every other team's rules with no coordination.

Full schemas for each kind are in the [Reference](#reference) section.

---

## Why Cedar

APF uses Cedar ([docs.cedarpolicy.com](https://docs.cedarpolicy.com)), the purpose-built authorization language from AWS, because governance policy must be auditable by the teams it affects, not just the team that wrote it. Unlike general-purpose policy languages, Cedar trades expressiveness for auditability — a `permit`/`forbid` statement is reviewable by security, legal, and compliance without policy-engineering expertise, and its deliberate constraints — no recursion, no side effects, no I/O — make that guarantee hold as bundles grow:

- **Auditability**: Security teams, legal, and operators can read Cedar statements without reading code.
- **Static type checking**: When `spec.schema` is present, all field references are type-checked at bundle compile time, not at request time.
- **Formal verifiability**: Cedar's policy set can be analyzed for conflicts, redundancy, and coverage using the Cedar verification toolkit.
- **Safe composition**: Multiple teams can contribute `PolicyRule` documents to a single bundle without worrying that one rule's evaluation can affect another's (no shared mutable state).

---

## Cedar conventions in APF

Understanding how APF maps requests onto Cedar's principal/action/resource model makes policy authoring much more predictable.

### Principal / action / resource mapping

Every Cedar rule evaluates against three slots populated from the normalized request:

| Slot | Populated from | Example |
|---|---|---|
| `principal` | Authenticated identity of the agent operator | `APF::User::"alice@corp.com"` |
| `action` | Tool capability being invoked | `APF::Action::"github::repo_read"` |
| `resource` | Tool being called | `APF::Tool::"github"` |

For plain HTTP traffic (non-MCP), action and resource are derived from the HTTP method and target host rather than an MCP envelope.

### `context.annotations`

Values produced by `PolicyAnnotator` documents, keyed by annotation name. Fully populated before any Cedar rule runs. Use `has` before reading string annotations — an unmatched annotator produces no key, and accessing an absent key is a Cedar error:

```cedar
// Bool annotation — safe to read directly (defaults to false when no annotator matched).
when { context.annotations.secret_detected }

// String annotation — always guard with has.
when {
  context.annotations has secret_kind &&
  context.annotations.secret_kind == "github_pat"
}
```

This is how content inspection (annotators) and policy decisions (Cedar rules) stay cleanly separated — annotators do the inspection work, Cedar reads the result.

### `context.data`

The `spec.data` mapping from the current `PolicyRule`, injected per-rule. Each rule sees only its own data block. This keeps operator-tunable values (approved channels, length limits, allowlisted IDs) out of Cedar statements — changing a constraint means updating the data block, not editing Cedar:

```cedar
when {
  context.args.channel == context.data.approved_channel &&
  context.args.text_len <= context.data.max_text_len
}
```

### `context.has_tool_name`

`true` for MCP tool calls, `false` for plain HTTP. Use this to scope a rule to one traffic type without duplicating the rule:

```cedar
// Deny MCP tool calls carrying a secret outright.
// REST requests with a secret are handled separately by a permit + redact effect.
forbid (principal, action, resource)
when { context.has_tool_name && context.annotations.secret_detected };
```

### First-deny semantics and manifest order

Rules are evaluated in bundle manifest order. The first rule that fires an explicit `forbid` stops evaluation immediately — no subsequent rules run. Because the first `forbid` wins, manifest ordering is significant when rules can conflict. Permits from all rules accumulate `@apf_effect` and `@apf_finding` references; the EffectEngine resolves them after all rules complete.

---

## Walkthrough: secret leakage prevention

This example traces how a bundle prevents credential leakage for both MCP tool calls and plain REST requests, showing all five document kinds working together.

### 1. The annotator detects secrets

The `secret-detector` annotator runs on every request body and sets:
- `secret_detected = true` if any credential pattern matches.
- `secret_kind = "<type>"` (e.g. `aws_access_key`) from the first match.

These values are available to every Cedar rule in the bundle.

### 2. Capability rules grant or skip

The `github-grants`, `slack-grants`, and `linear-grants` capability rules evaluate the tool call. If the requested action is not covered by any rule (e.g. `github::repo_write` has no permit), the request is denied at this stage.

### 3. The control rule enforces content policy

The `security-content-gate` control rule runs for all traffic:

```cedar
// MCP tool calls: deny outright when a secret is detected.
@apf_finding("secret-detected")
@id("deny-secret")
forbid (principal, action, resource)
when { context.has_tool_name && context.annotations.secret_detected };

// REST requests: replace the body (credential never reaches upstream).
@apf_effect("redact-wholesale")
@id("redact-secret-rest")
permit (principal, action, resource)
when { !context.has_tool_name && context.annotations.secret_detected };
```

For an MCP tool call carrying a secret, the `forbid` fires: evaluation stops, the request is denied, and the `secret-detected` finding is emitted.

For a REST request carrying a secret, the `permit` fires and evaluation continues to the EffectEngine.

### 4. The effect replaces the body

The `redact-wholesale` effect replaces the request body with a redaction notice and sets a header from the `secret_kind` annotation. The original credential never reaches the upstream service.

### 5. Findings are emitted

The `secret-detected` finding carries `type: secret_detected`, `severity: critical`, and a label resolved from the `secret_kind` annotation (e.g. `github_pat`). Findings appear in the evaluation result and are forwarded to audit infrastructure regardless of whether the request was allowed or denied.

---

# Reference

## Bundle manifest

A `PolicyBundle` is a YAML envelope that lists every member document by path and SHA-256 digest. The compiler verifies each digest at load time; a mismatch or missing file causes the bundle to be rejected before any evaluator is constructed.

All member documents share a common envelope:

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: <Kind>
metadata:
  name: <name>
spec:
  ...
```

### Envelope fields

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyBundle
metadata: {}

id: <string>              # stable identifier for this bundle
description: <string>     # human-readable label
policy_revision: <integer> # monotonic counter — must be greater than the last accepted revision
not_before: <RFC3339>     # bundle is invalid before this timestamp
expires_at: <RFC3339>     # bundle is invalid after this timestamp

manifest:
  - path: <relative-path> # path to the document file, relative to the bundle root
    sha256: <hex>         # SHA-256 digest of the file at that path
```

`policy_revision` is a monotonic counter enforced by the gateway's counter store. A bundle whose revision is not strictly greater than the last accepted revision is rejected, preventing rollback attacks.

`not_before` and `expires_at` define the validity window. The gateway rejects bundles outside this window at fetch time and will deny all requests once the active bundle expires.

### Manifest ordering

Documents are listed in the order the compiler and evaluator process them:

1. **`SandboxPolicy`** and **provider profiles** — admission-time documents; processed at sandbox creation, not per-request.
2. **`PolicyAnnotator`** documents — run in manifest order before any Cedar rule. Annotator output is available to all rules.
3. **`PolicyFinding`** and **`PolicyEffect`** documents — referenced by name from Cedar statements; must appear in the manifest before the rules that reference them.
4. **`PolicyRule`** documents — evaluated in manifest order. The first `forbid` that fires terminates evaluation; rule order determines which deny reason the caller receives when multiple rules could fire.

### Signature block

A signed bundle appends a YAML document separator and a signature record:

```yaml
---
schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
keyid: <key-id>
signature: <base64url>
```

The signature covers the canonical form of the bundle envelope and all manifest digests. The gateway verifies the signature against the trust root before accepting any bundle.

### Example

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyBundle
metadata: {}

id: acme-bundle
description: "Acme Corp agent policy bundle"
policy_revision: 7
not_before: "2026-01-01T00:00:00Z"
expires_at: "2027-01-01T00:00:00Z"

manifest:
  - path: sandbox/default-policy.yaml
    sha256: f4b9bb6abcc89c2e0800b71f29fd961f793ab152653e958a661da72827b71c5e

  - path: annotators/secret-detector.yaml
    sha256: 3f819ebf6d5437ebc3c64d75acb5a4e005137e9e0a62a418786c7cd31b890897

  - path: findings/secret-detected.yaml
    sha256: 4ea88b69e17bb70dafae71ecc922a0609dd9a4bbfe7558d040bd4e7a7fa5ee73

  - path: effects/redact-wholesale.yaml
    sha256: 7c7ffe8756bf7f7e89865416d4a1dc1297438bf1cebdb5495ecd446abe9b35dc

  - path: rules/github-grants.yaml
    sha256: c6abdb3a3b4225b505973759eb7765c18268ef8581c08be2e086f050b65bc320
  - path: rules/security-content-gate.yaml
    sha256: 8e852fe5680e9344adce75dde8f942336cf03e4a2b1bbf4cb1fe263182513ef1
---
schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
keyid: acme-prod
signature: <base64url>
```

---

## Stage 1: PolicyAnnotator

A `PolicyAnnotator` inspects request content and derives named values that Cedar policies read as `context.annotations.*`. All annotators in the bundle run before any Cedar rule. Their output is a flat key-value map injected into every rule's context.

### Schema

```yaml
spec:
  description: <string>           # optional, human-readable
  annotations:
    - name: <identifier>          # key under context.annotations.*
      output: bool | string | integer
      set_true_if: any | all      # for bool output: true when any/all rules match
      set_value_from: first_match # for string output: value from first matching rule
      rules:
        - field: <field>
          op: <op>
          pattern: <regex>        # for regex_match
          value: <string>         # result value (for string annotations) or match target (for equals)
          suffix: <string>        # for endswith
          prefix: <string>        # for startswith
          substring: <string>     # for contains
          threshold: <number>     # for gte / lte
          threshold_from: <field> # dynamic threshold from another field
```

**`field`** values:

| Value | Inspects |
|---|---|
| `body_text` | Decoded text of the request body |
| `body_json.<path>` | A specific path within a JSON body |
| `args.<name>` | A named MCP tool argument |
| `target.host` | Request target hostname |
| `target.path` | Request target path |
| `user_subject` | Authenticated subject |

**`op`** values:

| Op | Description |
|---|---|
| `regex_match` | Field matches `pattern` (RE2 syntax) |
| `equals` | Field exactly equals `value` |
| `endswith` | Field ends with `suffix` |
| `startswith` | Field starts with `prefix` |
| `contains` | Field contains `substring` |
| `length` | Field length compared to `threshold` (used with `gte`/`lte`) |
| `gte` | Field (as number) >= `threshold` |
| `lte` | Field (as number) <= `threshold` |
| `to_number` | Coerce field to number; match if conversion succeeds |
| `passthrough` | Always matches; copies the field value as-is |

### Example: secret detector

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyAnnotator
metadata:
  name: secret-detector
spec:
  description: Detects known credential shapes in request and result body text.
  annotations:
    - name: secret_detected
      output: bool
      set_true_if: any
      rules:
        - field: body_text
          op: regex_match
          pattern: 'sk-[A-Za-z0-9_-]{16,}'
        - field: body_text
          op: regex_match
          pattern: 'ghp_[A-Za-z0-9]{36}'
        - field: body_text
          op: regex_match
          pattern: '-----BEGIN.*PRIVATE KEY-----'
        - field: body_text
          op: regex_match
          pattern: 'AKIA[0-9A-Z]{16}'

    - name: secret_kind
      output: string
      set_value_from: first_match
      rules:
        - field: body_text
          op: regex_match
          pattern: 'sk-[A-Za-z0-9_-]{16,}'
          value: openai_key
        - field: body_text
          op: regex_match
          pattern: 'ghp_[A-Za-z0-9]{36}'
          value: github_pat
        - field: body_text
          op: regex_match
          pattern: 'AKIA[0-9A-Z]{16}'
          value: aws_access_key
```

### Example: PII detector

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyAnnotator
metadata:
  name: pii-detector
spec:
  description: Detects PII structural signatures in body text.
  annotations:
    - name: pii_detected
      output: bool
      set_true_if: any
      rules:
        - field: body_text
          op: regex_match
          pattern: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        - field: body_text
          op: regex_match
          pattern: '\b\d{3}-\d{2}-\d{4}\b'
        - field: body_text
          op: regex_match
          pattern: '\b(?:\d[ \-]?){13,16}\b'

    - name: pii_kind
      output: string
      set_value_from: first_match
      rules:
        - field: body_text
          op: regex_match
          pattern: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
          value: email
        - field: body_text
          op: regex_match
          pattern: '\b\d{3}-\d{2}-\d{4}\b'
          value: ssn
        - field: body_text
          op: regex_match
          pattern: '\b(?:\d[ \-]?){13,16}\b'
          value: payment_card
```

---

## Stage 2: PolicyRule

A `PolicyRule` carries one Cedar `PolicySet` evaluated against the fully-populated context. Each rule is a separate Cedar evaluation scope; rules do not share Cedar state.

### Schema

```yaml
spec:
  description: <string>
  language: cedar
  role: capability | control   # defaults to capability
  schema: |                    # optional Cedar schema in human syntax
    namespace APF { ... }
  definition: |                # Cedar policy statements
    permit ( ... );
    forbid ( ... );
  data:                        # optional YAML mapping; available as context.data
    key: value
```

### `spec.role`

**`capability`** (default): Grants access to specific tools or capabilities. For MCP tool calls, at least one `capability` rule must fire a `permit` or the request is denied — there is no ambient allow. Cedar default-deny (no permit matched, no explicit `forbid`) means the rule is not applicable; the evaluator skips it and continues. An explicit `forbid` stops evaluation immediately.

**`control`**: Enforces content policy for all traffic — MCP and plain HTTP. Permits may carry `@apf_effect` mutations but do **not** satisfy the `capability` requirement for MCP tool calls.

| Role | Applies to | Permit satisfies MCP grant? | Default-deny behavior |
|---|---|---|---|
| `capability` | MCP tool calls (skipped for non-MCP) | Yes | Skip rule, continue |
| `control` | All traffic | No | Skip rule, continue |

An explicit `forbid` in any rule, regardless of role, stops evaluation immediately.

### Cedar annotations on policy statements

APF defines three Cedar annotations that hook into the evaluation pipeline:

**`@id("reason")`** — assigns a human-readable label to a statement. Becomes the deny reason when this forbid is the determining statement. Convention: `<rule-name>/<label>`.

**`@apf_effect("name")`** — triggers a `PolicyEffect` by name when this `permit` fires. Valid only on `permit`; placing it on a `forbid` is a compile-time error.

**`@apf_finding("name")`** — triggers a `PolicyFinding` by name when this statement fires. Valid on both `permit` and `forbid`.

Both `@apf_effect` and `@apf_finding` references that do not resolve to a bundle document are compile-time errors — the bundle does not load.

### Deny reason format

The deny reason returned to callers takes the form `<rule-name>/<@id>`. Examples:

- `slack-grants: conditions not met for slack::slack_chat_post` — a capability rule exists but no permit matched.
- `no grant for github::repo_write` — no capability rule covers this tool/capability.
- `security-content-gate/deny-secret` — an explicit `forbid` fired.

### Example: capability rule

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyRule
metadata:
  name: slack-grants
spec:
  language: cedar
  role: capability
  data:
    approved_channel: "C0123456789"
    max_text_len: 2000
  definition: |
    @id("slack-grants/slack_chat_post")
    permit (
      principal,
      action == APF::Action::"slack::slack_chat_post",
      resource
    )
    when {
      context.args.channel == context.data.approved_channel &&
      context.args.text_len <= context.data.max_text_len
    };
```

### Example: control rule

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyRule
metadata:
  name: security-content-gate
spec:
  language: cedar
  role: control
  definition: |
    @id("baseline-allow")
    permit (principal, action, resource);

    @apf_finding("secret-detected")
    @id("deny-secret")
    forbid (principal, action, resource)
    when { context.has_tool_name && context.annotations.secret_detected };

    @apf_effect("redact-wholesale")
    @id("redact-secret-rest")
    permit (principal, action, resource)
    when { !context.has_tool_name && context.annotations.secret_detected };

    @apf_effect("redact-pii-body")
    @id("redact-pii-rest")
    permit (principal, action, resource)
    when { !context.has_tool_name && context.annotations.pii_detected };
```

---

## Stage 3: PolicyEffect

A `PolicyEffect` defines mutations applied to a request when a `permit` fires with `@apf_effect("name")`. Effects from all fired permits accumulate; header mutations from every fired permit are collected, body replacement uses the last fired effect that specifies one.

### Schema

```yaml
spec:
  description: <string>
  verdict: allow | warn | escalate
  reason: <string>               # optional, machine-readable code
  message: <string>              # optional, human-readable
  body:
    replace: <json-string>       # full body replacement
    patches:                     # RFC 6902 JSON Patch operations
      - op: replace | add | remove
        path: <json-pointer>
        value: <literal>
        source: <annotation-path> # value read from context.annotations.* at eval time
  headers:
    - name: <header-name>
      action: set | add | remove
      value: <literal>
      source: <annotation-path>
  finding: <name> | <inline-finding>
```

`source` reads from `context.annotations.*` at evaluation time. If the referenced annotation is absent, the request is denied (fail-closed).

### `spec.verdict`

| Value | Meaning |
|---|---|
| `allow` | Normal allow; no elevated signal |
| `warn` | Allow with elevated signal; suitable for audit |
| `escalate` | Allow but requires human review or escalation |

### Example: full body replacement

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyEffect
metadata:
  name: redact-wholesale
spec:
  verdict: allow
  reason: secret_pattern_redacted
  body:
    replace: '{"apf_redacted": true, "reason": "credential pattern detected"}'
  headers:
    - name: x-openshell-middleware-apf-event
      action: set
      source: context.annotations.secret_kind
  finding: secret-detected
```

### Example: body patch

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyEffect
metadata:
  name: redact-pii-body
spec:
  verdict: allow
  body:
    patches:
      - op: replace
        path: /text
        value: "[APF sanitized — PII detected in message. Original content withheld.]"
  finding:
    type: pii_redacted
    label: pii_in_body_text
    severity: medium
```

The `finding` here is an inline definition rather than a named reference.

---

## PolicyFinding

A `PolicyFinding` declares an observation type emitted alongside a decision — on both allows and denies — and forwarded to audit infrastructure.

### Schema

```yaml
spec:
  description: <string>
  type: <string>          # machine-readable category, e.g. secret_detected
  severity: low | medium | high | critical
  label: <string>         # static human-readable label
  label_source: <path>    # e.g. context.annotations.secret_kind
```

Exactly one of `label` or `label_source` should be present.

### Example

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyFinding
metadata:
  name: secret-detected
spec:
  type: secret_detected
  severity: critical
  label_source: context.annotations.secret_kind
```

### Referencing findings

From Cedar via `@apf_finding`:

```cedar
@apf_finding("secret-detected")
@id("deny-secret")
forbid (principal, action, resource)
when { context.has_tool_name && context.annotations.secret_detected };
```

From a `PolicyEffect` via the `finding` field:

```yaml
finding: secret-detected        # named reference
# OR inline:
finding:
  type: pii_redacted
  label: pii_in_body_text
  severity: medium
```

---

## SandboxPolicy

A `SandboxPolicy` controls what a sandbox may do at the network and filesystem level. Evaluated once at sandbox admission. The `SandboxPolicy` determines reachability; Cedar `PolicyRule` documents then govern what the agent may do within reachable endpoints.

```yaml
apiVersion: nvidia.agent-policy-fabric.sandbox/v1alpha1
kind: SandboxPolicy
```

### `spec.filesystem`

```yaml
filesystem:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /etc
  read_write:
    - /sandbox
    - /tmp
```

### `spec.network_policies`

Deny-default egress allowlist. Each entry describes an external endpoint the sandbox may reach.

```yaml
network_policies:
  github:
    name: github
    binaries:
      - path: /usr/bin/gh
      - path: /usr/bin/curl
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: read-only
        enforcement: enforce
```

`binaries` restricts which executables may open connections to the listed endpoints. `enforcement: enforce` blocks violations; `enforcement: audit` logs without blocking.

### `spec.network_middlewares`

Attaches named middleware to outbound HTTP requests for selected hosts.

```yaml
network_middlewares:
  apf_content_policy:
    name: APF content policy
    middleware: apf-content-policy
    order: 10
    on_error: fail_closed
    endpoints:
      include:
        - "api.github.com"
```

### `spec.landlock`

```yaml
landlock:
  compatibility: best_effort
```

### `spec.process`

```yaml
process:
  run_as_user: sandbox
  run_as_group: sandbox
```

---

## Bundle compile-time checks

The bundle compiler enforces the following before any bundle is accepted:

- Every `@apf_effect("name")` must resolve to a `PolicyEffect.metadata.name` in the bundle.
- Every `@apf_finding("name")` must resolve to a `PolicyFinding.metadata.name` in the bundle.
- `@apf_effect` on a `forbid` is a compile error.
- When `spec.schema` is present, all `context.*` field references are type-checked against the schema.

A bundle with any of these violations does not load — the evaluator is never constructed from an invalid bundle.

---

## Authoring checklist

When writing a new `PolicyRule`:

1. Choose `role: capability` for tool access grants; `role: control` for content inspection that applies to all traffic.
2. Place operator-tunable values (IDs, limits) in `spec.data` rather than hardcoding them in Cedar statements.
3. Provide `spec.schema` for any rule that uses `context.args.*` to catch field-name typos at compile time.
4. Use `@id("rule-name/label")` on every `forbid` so deny reasons are human-readable.
5. Prefer a separate `PolicyFinding` document over inline finding definitions when the same finding type is referenced from multiple rules or effects.
6. Do not place `@apf_effect` on a `forbid` — it is a compile error.
7. When reading a string annotation, guard with `context.annotations has <key>` to avoid Cedar errors on absent annotations.

When writing a new `PolicyAnnotator`:

1. Use `output: bool` with `set_true_if: any` for detection flags.
2. Use `output: string` with `set_value_from: first_match` for classification labels.
3. Test regex patterns carefully: RE2 syntax is used, not PCRE. Possessive quantifiers and lookaheads are not supported.
4. An annotator that matches no rules produces no key in `context.annotations`; Cedar policies that read the key must guard with `has`.
