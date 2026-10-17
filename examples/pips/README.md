# pips — example provider registrations

Registration files for `apf-policy-gateway --pip-config` (or `APF_PIP_CONFIG`),
one per way of connecting a policy information provider. The gateway consults
registered providers in the Enrichment stage, before any rule runs, and exposes
their facts to policy as `context.<domain>`, where the domain is the `context`
each registration declares.

| File | `type` | Connection | Shows |
|---|---|---|---|
| `http-bearer.yaml` | `http` | A JSON API the gateway calls itself, with a bearer token | `applies_to`, a lookup key with an anchored pattern, `record_path`, `must_match`, `keep`, and `timeout_ms`. |
| `grpc-https-mtls.yaml` | `grpc` | The `PolicyInformationService` contract over HTTPS with mutual TLS | The default way to connect a provider that implements the contract, with `applies_to` and `fail_closed`. |
| `grpc-unix-socket.yaml` | `grpc` | The contract over a Unix domain socket | A co-located provider with peer-UID verification, consulted on every request. |

Each file registers one provider. A real deployment lists all of its providers
in one file, at most 16, with one provider per context. The referenced TLS and
credential files do not exist in the repository; create them on the host with
the modes the comments describe before starting the gateway.

The gateway loads the file before any listener binds and refuses to start on
any validation error, including an unknown key. The key reference, the subject
projection, the `http` lookup rules, timeouts, provenance and the security
notes are in `docs/integrations/policy-information-providers.mdx`.
