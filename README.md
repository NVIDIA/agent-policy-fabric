# APF — Agent Policy Fabric

APF governs what agentic workloads are allowed to do. Policy is authored and signed once,
independent of any execution environment, letting the enterprise — not the developer or
the agent itself — set the rules every decision is evaluated against, rather than each
agent or host carrying its own hand-built version of "what's allowed."

## How it works

Every agent follows one governed path: admitted once under signed policy, then gated at every
layer on every action. Every layer has to agree before a call proceeds:

- **Sandbox containment and admission** (OpenShell) — what a sandbox can even attempt,
  and which tools it may reach at all.
- **Content and context** (APF's policy gateway) — whether an already-permitted call,
  given its arguments and target, actually holds up.

APF applies this to sandbox policy wherever agents run; OpenShell is the sandbox runtime
it's integrated with today.
- **Gateway interceptor** — at sandbox admission, injects the compiled `SandboxPolicy`
- **Supervisor middleware** — on every egress request, evaluates and returns the decision OpenShell enforces

See [Architecture](docs/architecture.md) for how policy is compiled, signed, distributed,
and evaluated without a cloud round-trip on the hot path.

## Documentation

- [Architecture](docs/architecture.md) — enterprise-governed policy for agentic flows, components, control/data plane split, deployment models
- [Governed path](docs/governed-path.md) — admission and per-action enforcement layers: where APF decides, where the runtime enforces
- [Policy model](docs/policy-model.md) — document kinds, Cedar conventions, bundle format
- [Policy publishing](docs/policy-publishing.md) — compile, sign, publish, distribute, hot-swap
- [AGENTS.md](AGENTS.md) — for agents and contributors working in this codebase

## Contributing

See `AGENTS.md` for build commands, DAG invariants, and commit conventions.

## License

Apache-2.0
