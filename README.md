<!-- rumdl-disable MD013 -->

# APF — Agent Policy Fabric

> **Project status:** APF is developed primarily by NVIDIA and follows internal roadmaps and development priorities. Community contributions are welcome and reviewed, but acceptance depends on how well they fit with project goals. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

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

See [Architecture](docs/about/architecture.mdx) for how policy is compiled, signed, distributed,
and evaluated without a cloud round-trip on the hot path.

## Documentation

- [Developer guide](docs/index.mdx) — the APF documentation: overview, getting started, policy authoring, bundle management, OpenShell integration, operations, and reference. Navigation is defined in [docs/index.yml](docs/index.yml)
- [Documentation contributor guide](docs/CONTRIBUTING.mdx) — conventions for writing and reviewing the developer guide
- [AGENTS.md](AGENTS.md) — for agents and contributors working in this codebase

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process and DCO
requirements. See [AGENTS.md](AGENTS.md) for build commands, DAG invariants,
and commit conventions. Project ownership is listed in
[MAINTAINERS.md](MAINTAINERS.md).

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md). Report suspected
vulnerabilities privately using the process in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

Third-party crate licenses and attribution are published in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt). [licenses/selections.json](licenses/selections.json) records the license APF selects for each upstream license expression, such as MIT for `r-efi`, and `scripts/third_party_licenses.py` regenerates the notice. See [License](docs/resources/license.mdx).
