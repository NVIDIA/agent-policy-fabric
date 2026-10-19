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

Licensed under the [Apache License 2.0](LICENSE). The Helm chart under
`deploy/helm/apf` links to the same file, so a packaged chart carries it.

Third-party crate licenses and attribution are published in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt). [licenses/selections.json](licenses/selections.json) records the license APF selects for each upstream license expression, such as MIT for `r-efi`, and `scripts/third_party_licenses.py` regenerates the notice. See [License](docs/resources/license.mdx).

### Upstream license copies

Some crates are published without the license or notice files of their
upstream repositories. [licenses/upstream/](licenses/upstream/) keeps copies
of those files, taken from each upstream repository at the revision the crate
was published from, and
[licenses/upstream/provenance.json](licenses/upstream/provenance.json)
records the source URL, revision and SHA-256 of every copy.
`scripts/third_party_licenses.py` adds their text to
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt). The copies come from
nine upstream projects and cover twelve crates:

| Upstream project | Crates | Files | What the files cover |
|---|---|---|---|
| [canardleteer/buf-rs](https://github.com/canardleteer/buf-rs) | buf-tools 1.73.0 | [`buf-tools-1.73.0-LICENSE`](licenses/upstream/buf-tools-1.73.0-LICENSE)<br>[`buf-tools-1.73.0-THIRD_PARTY_NOTICES.txt`](licenses/upstream/buf-tools-1.73.0-THIRD_PARTY_NOTICES.txt) | The MIT license, and the repository's `THIRD_PARTY_NOTICES.md`, which covers the Buf CLI that the crate downloads at build time |
| [anthropics/buffa](https://github.com/anthropics/buffa) | buffa-descriptor 0.9.2 | [`buffa-descriptor-0.9.2-LICENSE`](licenses/upstream/buffa-descriptor-0.9.2-LICENSE)<br>[`buffa-descriptor-0.9.2-descriptor.proto-NOTICE.txt`](licenses/upstream/buffa-descriptor-0.9.2-descriptor.proto-NOTICE.txt)<br>[`buffa-descriptor-0.9.2-plugin.proto-NOTICE.txt`](licenses/upstream/buffa-descriptor-0.9.2-plugin.proto-NOTICE.txt) | The Apache-2.0 license, and the BSD-3-Clause notices of the bundled Google Protocol Buffers `descriptor.proto` and `compiler/plugin.proto`, copied verbatim from the top of each file |
| [cedar-policy/cedar](https://github.com/cedar-policy/cedar) | cedar-policy, cedar-policy-core and cedar-policy-formatter 4.13.0 | [`cedar-policy-4.13.0-LICENSE`](licenses/upstream/cedar-policy-4.13.0-LICENSE)<br>[`cedar-policy-4.13.0-NOTICE`](licenses/upstream/cedar-policy-4.13.0-NOTICE) | The Apache-2.0 license and the repository's NOTICE file, shared by the three crates |
| [knurling-rs/defmt](https://github.com/knurling-rs/defmt) | defmt-parser 1.0.0 | [`defmt-parser-1.0.0-LICENSE-MIT`](licenses/upstream/defmt-parser-1.0.0-LICENSE-MIT) | The MIT license; the crate is MIT OR Apache-2.0 and APF selects MIT |
| [Stranger6667/jsonschema](https://github.com/Stranger6667/jsonschema) | jsonschema-regex 0.46.10 | [`jsonschema-regex-0.46.10-LICENSE`](licenses/upstream/jsonschema-regex-0.46.10-LICENSE) | The MIT license |
| [rust-lang/libm](https://github.com/rust-lang/libm) | libm 0.2.16 | [`libm-0.2.16-SOURCE-NOTICES.txt`](licenses/upstream/libm-0.2.16-SOURCE-NOTICES.txt) | The leading notice comments of 67 source files under `libm/src/math`, each labelled with its file, including the BSD-2-Clause notices of the bundled FreeBSD `exp2.rs` and `exp2f.rs`; the crate itself is MIT |
| [andrewhickman/prost-reflect](https://github.com/andrewhickman/prost-reflect) | prost-reflect 0.14.7 | [`prost-reflect-0.14.7-LICENSE-MIT`](licenses/upstream/prost-reflect-0.14.7-LICENSE-MIT) | The MIT license; the crate is MIT OR Apache-2.0 and APF selects MIT |
| [Nugine/simd](https://github.com/Nugine/simd) | uuid-simd and vsimd 0.8.0 | [`uuid-simd-0.8.0-LICENSE`](licenses/upstream/uuid-simd-0.8.0-LICENSE) | The MIT license, shared by the two crates |
| [tokio-rs/valuable](https://github.com/tokio-rs/valuable) | valuable 0.1.1 | [`valuable-0.1.1-LICENSE`](licenses/upstream/valuable-0.1.1-LICENSE) | The MIT license |

## Notice and disclaimer

**NOTICE AND DISCLAIMER: This software automatically retrieves, accesses or interacts with external materials.  Those retrieved materials are not distributed with this software and are governed solely by separate terms, conditions and licenses.  You are solely responsible for finding, reviewing and complying with all applicable terms, conditions, and licenses, and for verifying the security, integrity and suitability of any retrieved materials for your specific use case. This software is provided "AS IS", without warranty of any kind. The author makes no representations or warranties regarding any retrieved materials, and assumes no liability for any losses, damages, liabilities or legal consequences from your use or inability to use this software or any retrieved materials. Use this software and the retrieved materials at your own risk.**

For example, `cargo build` downloads the Buf CLI from the `bufbuild/buf`
GitHub releases through `buf-tools`, a build dependency of `yaml-sigil-core`.
The end-to-end test tooling in [e2e/](e2e/README.md) downloads the OpenShell
CLI and the agent-sandbox manifest, and pulls container images and the
OpenShell Helm chart; the [e2e prerequisites](e2e/README.md#prerequisites)
list where they come from. These materials are distributed separately from
APF.
