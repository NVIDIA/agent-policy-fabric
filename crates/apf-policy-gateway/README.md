# apf-policy-gateway

The APF host-side policy agent. Runs alongside the sandbox runtime to project
policy at admission and enforce it on every egress request.

It serves two distinct roles:

1. **Sandbox policy projection** — at sandbox admission, fetches the compiled
   `SandboxPolicy` projection from `apf-policy-service` and injects it into the
   sandbox as OpenShell annotations, establishing the network egress rules the
   sandbox will operate under
2. **Local Policy Decision Point (PDP)** — evaluates every egress request
   in-process via Cedar, without a cloud round-trip

## What it does

```
At startup:
  Connect to apf-policy-service → fetch + verify bundle
  Build Cedar evaluator from PolicyRule documents
  Start bundle watch loop (hot-swap evaluator on bundle change)

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
| `--openshell-middleware-addr` | `APF_OPENSHELL_MIDDLEWARE_ADDR` | — | Bind address for `SupervisorMiddlewareServer` (inbound — supervisor calls here per request) |

## Two enforcement seams

```
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

The interceptor establishes **what the sandbox can reach** (network policy).
The middleware decides **whether each specific request is permitted** given the
active policy rules and request content.

## Architecture

See `docs/architecture.md` for sequence diagrams of both seams.
See `docs/policy-model.md` for the policy model and document schemas.
