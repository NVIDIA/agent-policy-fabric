# apf-policy-gateway

The APF host-side policy agent. Runs alongside the sandbox runtime to project policy at admission and enforce it on every egress request.

It serves two distinct roles:

1. **Sandbox policy projection** — at sandbox admission, fetches the compiled `SandboxPolicy` projection from `apf-policy-service` and injects it into the sandbox as OpenShell annotations, establishing the network egress rules the sandbox will operate under
2. **Local Policy Decision Point (PDP)** — evaluates every egress request in-process via Cedar, without a cloud round-trip

## What it does

```text
At startup:
  Connect to apf-policy-service → fetch + verify bundle
  Build Cedar evaluator from PolicyRule documents
  Start bundle watch loop (hot-swap evaluator on bundle change)
  If an authenticated interceptor or middleware listener is enabled, load caller trust + TLS identity before listening

At sandbox admission (OpenShell control plane):
  GatewayInterceptorServer ← OpenShell gateway calls here
  → fetch compiled SandboxPolicy projection from apf-policy-service
  → verify provenance JWT
  → inject as apf.nvidia.com/* annotations on the sandbox

Per egress request (OpenShell data plane):
  SupervisorMiddlewareServer ← OpenShell supervisor calls here
  → call EvaluationService/Evaluate (local Cedar)
  → return: allow/deny + body patches + header mutations + findings
```

## Key flags

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--socket` | `APF_GATEWAY_SOCKET` | `/run/apf/policy-gateway.sock` | UDS for `EvaluationService` |
| `--policy-service-socket` | `APF_POLICY_SERVICE_SOCKET` | `/run/apf/policy-service.sock` | Policy-service UDS to connect to |
| `--trust-root-dir` | `APF_TRUST_ROOT_DIR` | `./trust-roots` | Trust root keys for bundle verification |
| `--document-key-id` | `APF_DOCUMENT_KEY_ID` | `apf-dev` | Key ID for provenance JWT verification |
| `--jwks-url` | `APF_JWKS_URL` | — | Policy-service JWKS for provenance verification |
| `--openshell-gateway-url` | `APF_OPENSHELL_GATEWAY_URL` | — | OpenShell gateway URL (outbound — profile reconciliation, sandbox refresh) |
| `--openshell-interceptor-addr` | `APF_OPENSHELL_INTERCEPTOR_ADDR` | — | Bind address for `GatewayInterceptorServer` (inbound — OpenShell gateway calls here at sandbox admission) |
| `--openshell-interceptor-auth-trust-file` | `APF_OPENSHELL_INTERCEPTOR_AUTH_TRUST_FILE` | — | TOML profile for verifying OpenShell extension JWTs on the interceptor listener |
| `--openshell-interceptor-tls-cert-file` | `APF_OPENSHELL_INTERCEPTOR_TLS_CERT_FILE` | — | PEM certificate chain served by the interceptor HTTPS listener |
| `--openshell-interceptor-tls-key-file` | `APF_OPENSHELL_INTERCEPTOR_TLS_KEY_FILE` | — | PEM private key for the interceptor HTTPS listener |
| `--openshell-interceptor-allow-insecure-transport` | `APF_OPENSHELL_INTERCEPTOR_ALLOW_INSECURE_TRANSPORT` | `false` | Explicitly disable interceptor TLS and caller authentication for local research |
| `--openshell-middleware-addr` | `APF_OPENSHELL_MIDDLEWARE_ADDR` | — | Bind address for `SupervisorMiddlewareServer` (inbound — supervisor calls here per request) |
| `--openshell-middleware-auth-trust-file` | `APF_OPENSHELL_MIDDLEWARE_AUTH_TRUST_FILE` | — | TOML profile for verifying OpenShell extension JWTs on the middleware listener |
| `--openshell-middleware-tls-cert-file` | `APF_OPENSHELL_MIDDLEWARE_TLS_CERT_FILE` | — | PEM certificate chain served by the middleware HTTPS listener |
| `--openshell-middleware-tls-key-file` | `APF_OPENSHELL_MIDDLEWARE_TLS_KEY_FILE` | — | PEM private key for the middleware HTTPS listener |
| `--openshell-middleware-allow-insecure-transport` | `APF_OPENSHELL_MIDDLEWARE_ALLOW_INSECURE_TRANSPORT` | `false` | Explicitly disable middleware TLS and caller authentication for local research |

## OpenShell extension authentication

The interceptor and middleware listeners share one verifier and trust-file
format; the walkthrough below uses the middleware flags, but everything
applies identically to the interceptor with `--openshell-interceptor-*` flags
and audience prefix `urn:openshell:extension:interceptor:<name>`.

Production registrations use HTTPS plus an OpenShell extension bearer JWT. Configure the listener address, extension trust profile, TLS certificate chain, and TLS private key together. The gateway rejects partial combinations before it opens the listener. Supplying security settings without the listener's `--openshell-{interceptor,middleware}-addr` also fails startup.

The TLS certificate must be valid for the hostname in the OpenShell registration's endpoint and chain to a CA trusted by OpenShell. The extension trust profile authenticates inbound OpenShell callers; it is separate from APF bundle trust (`--trust-root-dir`) and policy-document provenance trust (`--jwks-url` and `--document-key-id`). Those APF trust settings cannot replace the extension trust profile.

The trust profile is strict TOML and rejects unknown fields:

```toml
issuer = "openshell-gateway:<gateway-id>"
audience = "urn:openshell:extension:middleware:apf-content-policy"
kid = "<OpenShell signing key id>"
public_key_pem = """
-----BEGIN PUBLIC KEY-----
<OpenShell Ed25519 public key>
-----END PUBLIC KEY-----
"""
max_lifetime_secs = 3600
leeway_secs = 60
```

For an OpenShell middleware registration named `apf-content-policy`, OpenShell resolves an omitted registration audience to `urn:openshell:extension:middleware:apf-content-policy`. For an interceptor registration named `apf/policy-adapter`, the equivalent default is `urn:openshell:extension:interceptor:apf/policy-adapter`. Use that exact value in this trust profile. If the OpenShell registration sets an explicit `audience`, copy that exact value here instead. `issuer` and `kid` must likewise match the OpenShell gateway identity and signing authority. `max_lifetime_secs` must be between 1 and 3600; `leeway_secs` must be no greater than 300. The verifier accepts exactly one `authorization: Bearer <JWT>` value and requires `alg=EdDSA`, `typ=openshell-ext+jwt`, the configured `kid`, exact scalar issuer and audience claims, a nonempty `jti`, and a bounded positive lifetime.

### Checked security files

The gateway opens the trust profile, TLS certificate, and TLS private key without following a symlink, then checks the metadata and reads bytes from that same opened inode. The trust profile and certificate must be regular files with no group or world write bits. The private key must be a regular owner-only file, normally mode `0600` or `0400`; any group or world permission bit rejects it. Directories, FIFOs, sockets, devices, symlinks, and other non-regular inputs fail startup.

The authenticated-mode preflight parses the trust profile, Ed25519 public key, TLS certificate chain, and TLS private key into the server configuration before any listener is allowed to report ready. A missing file, unsafe mode, invalid trust value, malformed certificate, or malformed key therefore stops the process instead of producing a partially ready service or falling back to plaintext.

For files provisioned directly on a Unix host, set compatible modes with fish:

```fish
chmod 0644 /etc/apf/openshell-extension-auth.toml /etc/apf/tls/middleware-cert.crt
chmod 0600 /etc/apf/tls/middleware-key.pk8
```

Start both authenticated listeners with fish-compatible flags:

```fish
apf-policy-gateway \
  --openshell-interceptor-addr 0.0.0.0:18099 \
  --openshell-interceptor-auth-trust-file /etc/apf/openshell-interceptor-auth.toml \
  --openshell-interceptor-tls-cert-file /etc/apf/tls/interceptor-cert.crt \
  --openshell-interceptor-tls-key-file /etc/apf/tls/interceptor-key.pk8 \
  --openshell-middleware-addr 0.0.0.0:9099 \
  --openshell-middleware-auth-trust-file /etc/apf/openshell-middleware-auth.toml \
  --openshell-middleware-tls-cert-file /etc/apf/tls/middleware-cert.crt \
  --openshell-middleware-tls-key-file /etc/apf/tls/middleware-key.pk8
```

On the middleware listener, authenticated `Describe` accepts a gateway or supervisor caller and advertises the configured audience in `MiddlewareManifest.expected_audience`. `ValidateConfig` accepts only a gateway caller. `EvaluateHttpRequest` accepts only a supervisor caller, and the authenticated JWT `sandbox_id` must equal `request.context.sandbox_id` before APF evaluates the request.

On the interceptor listener, authenticated `Describe`, `SnapshotProviderProfiles`, and `Evaluate` all accept a gateway caller only and advertise the configured audience in `InterceptorManifest.expected_audience` — the interceptor is exclusively called by the OpenShell gateway at admission time, so there is no supervisor-caller path and no sandbox-binding check on this surface.

For trusted local development or isolated research only, pass `--openshell-{interceptor,middleware}-allow-insecure-transport` with the corresponding listener address and omit that surface's three authenticated-mode files. The matching OpenShell registration must set `allow_insecure_transport = true`. This mode serves plaintext gRPC, does not require or verify an extension credential, advertises an empty `expected_audience`, and logs a startup warning. It cannot be combined with any authenticated-mode setting for the same surface.

## Two enforcement seams

```text
apf-policy-service
      │
      │ (1) GetDocument → compiled SandboxPolicy bytes
      │                   (network egress rules for the sandbox)
      ▼
apf-policy-gateway ──── hosts ───▶ GatewayInterceptorServer
      │                            (OpenShell control plane: sandbox admission)
      │
      │ (2) EvaluationService/Evaluate
      │     (Cedar decision per egress request)
      ▼
apf-policy-gateway ──── hosts ───▶ SupervisorMiddlewareServer
                                   (OpenShell data plane: per-request)
```

The interceptor establishes **what the sandbox can reach** (network policy). The middleware decides **whether each specific request is permitted** given the active policy rules and request content.

## Architecture

See `docs/about/governed-path.mdx` for the admission and per-request flows of both seams.
See `docs/author-policies/policy-model.mdx` for the policy model and
`docs/reference/policy-schemas.mdx` for the document schemas.
