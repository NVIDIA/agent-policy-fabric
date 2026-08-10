# APF — Agent Policy Fabric

APF is the policy layer for agentic workloads. It answers two questions at runtime:
*what is this agent allowed to do?* and *did it do exactly that?*

Policy is authored once, signed, and distributed to every host where agents run.
Enforcement happens locally — on the network egress path, at tool invocation, and
at sandbox admission — without a cloud round-trip on the hot path.

## How it works

```
Policy author  →  apf-policy-service  →  signed bundle
                                              ↓
                                    apf-policy-gateway (on host)
                                    • verifies bundle locally
                                    • evaluates every request in-process
                                    • enforces: allow / deny / redact
```

OpenShell is the first supported runtime. APF integrates at two hooks:
- **Gateway interceptor** — at sandbox admission, injects the compiled `SandboxPolicy`
- **Supervisor middleware** — on every egress request, evaluates and enforces

## Documentation

- [Architecture](docs/architecture.md) — component responsibilities, data/control plane flows, sequence diagrams
- [AGENTS.md](AGENTS.md) — for agents and contributors working in this codebase

## Contributing

See `AGENTS.md` for build commands, DAG invariants, and commit conventions.

## License

Apache-2.0
