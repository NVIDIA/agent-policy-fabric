# APF Policy Language Reference

APF policy is authored as a bundle of YAML documents. The evaluator processes every request in three stages:

1. **AnnotatorEngine** — runs all `PolicyAnnotator` documents (in parallel) against the request, producing a `context.annotations.*` map.
2. **Cedar Evaluator** — evaluates each `PolicyRule.definition` in bundle order against the fully-populated context, collecting permit/forbid decisions and `@apf_effect`/`@apf_finding` references.
3. **EffectEngine** — resolves the collected effect and finding references, applies body mutations and header changes, and emits findings alongside the final decision.

---

## Why Cedar

APF uses Cedar ([docs.cedarpolicy.com](https://docs.cedarpolicy.com)) rather than a general-purpose language. The deliberate constraints Cedar imposes — no recursion, no side effects, no I/O — are features in a multi-team governance model:

- **Auditability**: Security teams, legal, and operators can read Cedar statements without reading code.
- **Static type checking**: When `spec.schema` is present, all `context.*` field references are type-checked at bundle compile time, not at request time.
- **Formal verifiability**: Cedar's policy set can be analyzed for conflicts, redundancy, and coverage using the Cedar verification toolkit.
- **Safe composition**: Multiple teams can contribute `PolicyRule` documents to a single bundle without worrying that one rule's evaluation can affect another's (no shared mutable state).

---

## Bundle members

A bundle lists its members in the `manifest` section. Each member is a YAML file under the bundle root. The `kind` field selects the document type:

| Kind | API version | Purpose |
|---|---|---|
| `PolicyRule` | `nvidia.agent-policy-fabric.policy/v1alpha1` | Cedar policy statements that allow or deny requests |
| `PolicyAnnotator` | `nvidia.agent-policy-fabric.policy/v1alpha1` | Derives annotation values from request content for use in Cedar |
| `PolicyEffect` | `nvidia.agent-policy-fabric.policy/v1alpha1` | Mutations applied to allowed requests (body, headers) |
| `PolicyFinding` | `nvidia.agent-policy-fabric.policy/v1alpha1` | Observation records emitted alongside decisions |
| `SandboxPolicy` | `nvidia.agent-policy-fabric.sandbox/v1alpha1` | Network egress allowlist for sandbox admission (OpenShell-specific) |

All documents share a common envelope:

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: <Kind>
metadata:
  name: <name>
spec:
  ...
```

---

## EvalInput: how requests are normalized

Before any policy runs, the evaluator normalizes the incoming request into an `EvalInput`. Understanding the fields available in Cedar `context` requires knowing this model.

| EvalInput field | Cedar location | Description |
|---|---|---|
| `user_subject` | `principal: APF::User::"<value>"` | Authenticated identity of the agent operator |
| `tool` | `resource: APF::Tool::"<name>"` | MCP tool name (e.g. `github`, `slack`) |
| `capability` | `action: APF::Action::"<tool>::<cap>"` | Tool capability (e.g. `github::repo_read`) |
| `args.*` | `context.args.*` | MCP tool call arguments, pre-flattened |
| `body_text` | Consumed by annotators | Decoded text of the request body |
| `has_tool_name` | `context.has_tool_name` | `true` for MCP tool calls, `false` for plain HTTP |

For non-MCP HTTP traffic, `tool` and `capability` are derived from the HTTP method and target rather than an MCP envelope.

String arguments are strings in Cedar; numeric arguments (counts, lengths) are exposed as `Long` so Cedar's numeric operators apply directly. The `args.*` record contains only the fields present in the request; Cedar's `has` operator tests for field presence.

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

### Using annotations in Cedar

Read bool annotations directly:

```cedar
when { context.annotations.secret_detected }
```

For string annotations, use the `has` guard because the annotation is absent when no rule matched:

```cedar
when {
  context.annotations has pii_kind &&
  context.annotations.pii_kind == "email"
}
```

---

## Stage 2: PolicyRule

A `PolicyRule` carries one Cedar `PolicySet` evaluated against the fully-populated context. Each rule is a separate Cedar evaluation scope; rules do not share Cedar state.

### Schema

```yaml
spec:
  description: <string>   # optional
  language: cedar         # only value currently supported
  role: capability | control   # see below; defaults to capability
  schema: |               # optional Cedar schema in human syntax
    namespace APF { ... }
  definition: |           # Cedar policy statements
    permit ( ... );
    forbid ( ... );
  data:                   # optional YAML mapping; available as context.data
    key: value
```

### `spec.role`

Controls how the evaluator interprets this rule's Cedar default-deny:

**`capability`** (default): This rule grants access to specific tools or capabilities. For MCP tool calls, at least one `capability` rule must fire a Cedar `permit` or the request is denied — there is no ambient allow for tool calls. Cedar default-deny (no permit matched, no explicit `forbid`) means the rule is not applicable to this request; the evaluator skips it and continues to the next rule. An explicit `forbid` stops evaluation immediately and returns deny.

**`control`**: This rule enforces content policy for all traffic — both MCP tool calls and plain HTTP requests. Permits on a `control` rule pass traffic through and may carry `@apf_effect` mutations, but they do **not** satisfy the `capability` requirement for MCP tool calls. Cedar default-deny is still a skip; only an explicit `forbid` stops evaluation.

| Role | Applies to | Permit satisfies MCP grant? | Default-deny behavior |
|---|---|---|---|
| `capability` | MCP tool calls (skipped for non-MCP) | Yes | Skip rule, continue |
| `control` | All traffic | No | Skip rule, continue |

An explicit `forbid` in any rule, regardless of role, stops evaluation immediately.

### `spec.schema` (optional)

Cedar schema in human syntax. When present, policy statements are type-checked against the schema at bundle compile time. When absent, statements compile without schema validation (field access errors surface at evaluation time).

Example:

```cedar
namespace APF {
  entity User;
  entity Tool;
  action "outlook::message_search" appliesTo {
    principal: [User],
    resource:  [Tool],
    context: {
      args: {
        folder:    String,
        limit_num: Long,
      },
    }
  };
}
```

### `spec.definition`

The Cedar policy statements. Must contain only policy statements — Cedar schema syntax in this field is rejected at compile time. The evaluator rejects bundles where a rule's `definition` looks like it contains a schema (the error message directs the author to use `spec.schema`).

### `spec.data` (optional)

An opaque YAML mapping injected into Cedar as `context.data`. Use this to keep operator-tunable values separate from policy logic so that changing a constraint (e.g. an allowed channel ID or a length limit) requires only a data update, not a Cedar statement edit.

```yaml
data:
  approved_channel: "C0123456789"
  max_text_len: 2000
```

Each rule sees only its own `data` block.

### Example: capability rule with data-driven constraints

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyRule
metadata:
  name: slack-grants
spec:
  description: Grants for Slack MCP capabilities via the network egress gateway. Approved channel is data-driven.
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

### Example: control rule for content inspection

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyRule
metadata:
  name: security-content-gate
spec:
  description: >
    Content security gate — deny secret leakage, redact PII. Evaluates for
    all traffic (MCP and non-MCP). role: control means this rule does not
    satisfy the MCP capability requirement; it only enforces content policy.
  language: cedar
  role: control
  definition: |
    // Baseline allow — fires for every request so effects from other permits
    // in this PolicySet are collected even when no content is flagged.
    @id("baseline-allow")
    permit (principal, action, resource);

    // MCP tool calls carrying a detected secret are denied outright.
    @apf_finding("secret-detected")
    @id("deny-secret")
    forbid (principal, action, resource)
    when { context.has_tool_name && context.annotations.secret_detected };

    // REST requests carrying a secret: replace the full body before forwarding.
    @apf_effect("redact-wholesale")
    @id("redact-secret-rest")
    permit (principal, action, resource)
    when { !context.has_tool_name && context.annotations.secret_detected };

    // REST requests with PII in body: patch the /text field before forwarding.
    @apf_effect("redact-pii-body")
    @id("redact-pii-rest")
    permit (principal, action, resource)
    when { !context.has_tool_name && context.annotations.pii_detected };
```

### Cedar annotations on policy statements

APF defines three Cedar annotations that hook into the evaluation pipeline:

**`@id("reason")`** — assigns a human-readable label to a policy statement. The label becomes the deny reason when this statement is the determining forbid. Convention: `<rule-name>/<label>`, e.g. `@id("github-grants/repo_read")`. When the `@id` already contains a slash it is used verbatim.

**`@apf_effect("name")`** — triggers a `PolicyEffect` by name when this `permit` fires. Valid only on `permit` statements; placing it on a `forbid` is a compile-time error. The named effect must exist in the bundle.

**`@apf_finding("name")`** — triggers a `PolicyFinding` by name when this statement fires. Valid on both `permit` and `forbid`. On `forbid`, the finding accompanies the deny. On `permit`, the finding is collected alongside the allow. The named finding must exist in the bundle.

Both `@apf_effect` and `@apf_finding` references that do not resolve to a bundle document are compile-time errors — the bundle does not load.

### Cedar extension functions

APF registers the following Cedar extension functions for use in `when` clauses:

| Function | Signature | Description |
|---|---|---|
| `apf::regex::matches` | `(String, String) -> Bool` | Tests whether the first argument matches the RE2 regex in the second |
| `apf::str::ends_with` | `(String, String) -> Bool` | Tests whether the string ends with the suffix |
| `apf::str::length` | `(String) -> Long` | Returns the byte length of the string |
| `apf::num::coerce` | `(String\|Long) -> Long` | Converts a string to a Long; returns 0 on conversion failure |

Example:

```cedar
permit (principal, action == APF::Action::"slack::post", resource)
when {
  apf::str::length(context.args.message) <= 2000 &&
  apf::regex::matches(context.args.channel, "^C[A-Z0-9]{8}$")
};
```

### Evaluation order and first-deny semantics

Rules are evaluated in bundle manifest order. Within each rule, Cedar evaluates all statements in the `PolicySet`.

- The first rule that fires an explicit `forbid` stops evaluation immediately; remaining rules in the bundle are not evaluated.
- Permits from all rules accumulate `@apf_effect` and `@apf_finding` references.
- After all rules, the EffectEngine resolves collected references in the order they were gathered.

Because the first `forbid` wins, bundle manifest order is significant when rules can conflict.

### Deny reason format

The deny reason returned to callers takes the form `<rule-name>/<@id>`. Examples:

- `slack-grants: conditions not met for slack::slack_chat_post` — a capability rule exists for this tool but no permit matched the request arguments.
- `no grant for github::repo_write` — no capability rule covers this tool/capability.
- `security-content-gate/deny-secret` — an explicit `forbid` with `@id("deny-secret")` fired in the `security-content-gate` rule.

---

## Stage 3: PolicyEffect

A `PolicyEffect` defines mutations applied to a request when a `permit` fires with `@apf_effect("name")`. Effects from all fired permits accumulate in policy order within each rule and rule order across the bundle. Header mutations from every fired permit are collected; body replacement uses the last fired effect that specifies one.

### Schema

```yaml
spec:
  description: <string>        # optional
  verdict: allow | warn | escalate
  reason: <string>             # optional, machine-readable code
  message: <string>            # optional, human-readable
  body:
    replace: <json-string>     # full body replacement (mutually exclusive with patches)
    patches:                   # RFC 6902 JSON Patch operations
      - op: replace | add | remove
        path: <json-pointer>   # e.g. /text
        value: <literal>       # literal replacement value
        source: <annotation-path>  # value read from context.annotations.* at eval time
  headers:
    - name: <header-name>
      action: set | add | remove
      value: <literal>         # literal header value
      source: <annotation-path>  # value from context.annotations.* at eval time
  finding: <name> | <inline-finding>
```

`source` on a patch or header reads from `context.annotations.*` at evaluation time. If the referenced annotation is absent, the request is denied with a runtime error (fail-closed).

### `spec.verdict`

The highest-severity verdict among all fired effects wins.

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
  description: Replace full body with a redaction notice and emit a secret finding.
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

The `source: context.annotations.secret_kind` on the header causes the header value to be filled from the `secret_kind` annotation at evaluation time (e.g. `github_pat`, `aws_access_key`).

### Example: body patch

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyEffect
metadata:
  name: redact-pii-body
spec:
  description: Replace the JSON body's text field with a sanitization notice on PII detection.
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

The `finding` here is an inline definition rather than a named reference. Inline findings follow the `PolicyFinding` spec format but live inside the `PolicyEffect`.

---

## PolicyFinding

A `PolicyFinding` declares an observation type. Findings appear alongside the evaluation result whether the request was allowed or denied:

- On `forbid`: the finding named in `@apf_finding` accompanies the deny.
- On `permit` with an effect that references a finding: the finding accompanies the allow.

### Schema

```yaml
spec:
  description: <string>   # optional
  type: <string>          # machine-readable category, e.g. secret_detected
  severity: low | medium | high | critical
  label: <string>         # optional, static human-readable label
  label_source: <path>    # optional, e.g. context.annotations.secret_kind
```

Exactly one of `label` or `label_source` should be present. `label_source` resolves to the annotation's string value at evaluation time (e.g. `github_pat`).

### Example

```yaml
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyFinding
metadata:
  name: secret-detected
spec:
  description: Credential material observed in outbound or inbound content.
  type: secret_detected
  severity: critical
  label_source: context.annotations.secret_kind
```

### Referencing findings

From a Cedar `forbid` via `@apf_finding`:

```cedar
@apf_finding("secret-detected")
@id("deny-secret")
forbid (principal, action, resource)
when { context.has_tool_name && context.annotations.secret_detected };
```

From a `PolicyEffect` via the `finding` field (named reference or inline definition):

```yaml
finding: secret-detected        # named reference
# OR
finding:
  type: pii_redacted
  label: pii_in_body_text
  severity: medium
```

---

## SandboxPolicy

A `SandboxPolicy` is an OpenShell-specific document that controls what a sandbox may do at the network and filesystem level. It is evaluated at sandbox admission time, before any Cedar rules. The `SandboxPolicy` determines reachability; the Cedar `PolicyRule` documents then govern what the agent may do within reachable endpoints.

`SandboxPolicy` uses a separate `apiVersion`:

```yaml
apiVersion: nvidia.agent-policy-fabric.sandbox/v1alpha1
kind: SandboxPolicy
```

### `spec.filesystem`

Declares readable and writable paths for the sandbox process.

```yaml
filesystem:
  include_workdir: true   # add the current working directory to the allowed set
  read_only:
    - /usr
    - /lib
    - /etc
  read_write:
    - /sandbox
    - /tmp
    - /dev/null
```

### `spec.network_policies`

Deny-default egress allowlist. Each named entry describes an external endpoint the sandbox may reach.

```yaml
network_policies:
  github:
    name: github
    binaries:
      - path: /usr/bin/gh     # restrict to these executables
      - path: /usr/bin/curl
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: read-only
        enforcement: enforce
  httpbin:
    name: httpbin
    endpoints:
      - host: httpbin.org
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: /anything
```

`binaries` restricts which executables may open connections to the listed endpoints. `rules` adds L7 method/path constraints. `enforcement: enforce` blocks violations; `enforcement: audit` logs without blocking.

### `spec.network_middlewares`

Attaches named middleware to outbound HTTP requests for selected hosts. The APF content policy middleware evaluates each outbound HTTP request against the Cedar engine before credentials are injected.

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
        - "host.openshell.internal"
```

`order` controls middleware chain position (lower runs first). `on_error: fail_closed` denies the request if the middleware itself errors.

### `spec.landlock`

Linux Landlock filesystem restriction settings.

```yaml
landlock:
  compatibility: best_effort
```

`best_effort` applies Landlock restrictions where supported and skips silently on kernels without support.

### `spec.process`

```yaml
process:
  run_as_user: sandbox
  run_as_group: sandbox
```

---

## Cedar conventions in APF

### Principal / action / resource mapping

| APF concept | Cedar slot | Example Cedar value |
|---|---|---|
| Authenticated user | `principal` | `APF::User::"alice@corp.com"` |
| Tool capability | `action` | `APF::Action::"github::repo_read"` |
| Tool name | `resource` | `APF::Tool::"github"` |

For non-MCP HTTP traffic the action and resource reflect the HTTP method and target host.

### `context.has_tool_name`

`true` for MCP tool calls, `false` for plain HTTP requests. Use this to write policies that apply to only one traffic type:

```cedar
// Deny MCP tool calls carrying a secret; non-MCP requests are handled by a permit+effect.
forbid (principal, action, resource)
when { context.has_tool_name && context.annotations.secret_detected };
```

### `context.args`

MCP tool call arguments, pre-flattened into the Cedar context. Numeric arguments are `Long`; string arguments are `String`. Use `has` to test for argument presence before reading:

```cedar
permit (principal, action == APF::Action::"linear::list_issues", resource)
when {
  context.args.team == context.data.approved_team &&
  context.args.project == context.data.approved_project
};
```

### `context.annotations`

Values produced by `PolicyAnnotator` documents, keyed by annotation name. Fully populated before any Cedar rule runs. Use `has` before reading string annotations because an unmatched annotator produces no key (accessing an absent key is a Cedar error):

```cedar
// Bool annotation — safe to read directly (annotators default to false).
when { context.annotations.secret_detected }

// String annotation — guard with has.
when {
  context.annotations has secret_kind &&
  context.annotations.secret_kind == "github_pat"
}
```

### `context.data`

The `spec.data` mapping from the current `PolicyRule`, injected per-rule. Each rule sees only its own data block. Use this to parameterize policies without editing Cedar statements:

```cedar
when { context.args.channel == context.data.approved_channel }
```

### Bundle compile-time checks

The bundle compiler enforces the following at compile time (not at request time):

- Every `@apf_effect("name")` must resolve to a `PolicyEffect.metadata.name` in the bundle.
- Every `@apf_finding("name")` string reference must resolve to a `PolicyFinding.metadata.name` in the bundle.
- `@apf_effect` on a `forbid` is a compile error.
- When `spec.schema` is present, all `context.*` field references in the `definition` are type-checked against the schema.

A bundle with any of these violations does not load — the evaluator is never constructed from an invalid bundle.

---

## Walkthrough: secret leakage prevention

This example traces how the demo-bundle prevents credential leakage for both MCP tool calls and plain REST requests.

### 1. The annotator detects secrets

The `secret-detector` annotator runs on the request body and sets:
- `context.annotations.secret_detected = true` if any credential pattern matches.
- `context.annotations.secret_kind = "<type>"` (e.g. `aws_access_key`) from the first match.

### 2. Capability rules grant or skip

The `github-grants`, `slack-grants`, and `linear-grants` capability rules evaluate the tool call. If the requested action is not in scope for any rule (e.g. `github::repo_write` has no permit), the request is denied at this stage.

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

For a REST request carrying a secret, the `permit` fires: evaluation continues to the EffectEngine.

### 4. The effect replaces the body

The `redact-wholesale` effect replaces the request body with `{"apf_redacted": true, "reason": "credential pattern detected"}` and sets the `x-openshell-middleware-apf-event` header from `context.annotations.secret_kind`. The original credential never reaches the upstream service.

### 5. Findings are emitted

The `secret-detected` finding carries `type: secret_detected`, `severity: critical`, and a label resolved from `context.annotations.secret_kind` (e.g. `github_pat`). Findings appear in the evaluation result and are forwarded to audit infrastructure regardless of whether the request was allowed or denied.

---

## Authoring checklist

When writing a new `PolicyRule`:

1. Choose `role: capability` for tool access grants; choose `role: control` for content inspection that applies to all traffic.
2. Place operator-tunable values (IDs, limits) in `spec.data` rather than hardcoding them in Cedar statements.
3. Provide `spec.schema` for any rule that uses `context.args.*` to catch field-name typos at compile time.
4. Use `@id("rule-name/label")` on every `forbid` so deny reasons are human-readable.
5. Prefer a separate `PolicyFinding` document over inline finding definitions when the same finding type is referenced from multiple rules or effects.
6. Do not place `@apf_effect` on a `forbid` — it is a compile error.
7. When reading a string annotation from `context.annotations`, guard with `context.annotations has <key>` to avoid Cedar errors on absent annotations.

When writing a new `PolicyAnnotator`:

1. Use `output: bool` with `set_true_if: any` for detection flags (`secret_detected`, `pii_detected`).
2. Use `output: string` with `set_value_from: first_match` for classification labels (`secret_kind`, `pii_kind`).
3. Test regex patterns carefully: RE2 syntax is used, not PCRE. Possessive quantifiers and lookaheads are not supported.
4. An annotator that matches no rules produces no key in `context.annotations`; Cedar policies that read the key must guard with `has`.
