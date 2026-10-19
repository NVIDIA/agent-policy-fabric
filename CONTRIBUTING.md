# Contributing to NVIDIA Agent Policy Fabric

Thank you for your interest in contributing to NVIDIA Agent Policy Fabric (APF).

A contribution is ready for review when it makes the smallest complete change,
includes appropriate validation, and follows the pull request template.

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md). Report
security vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue
or pull request.

## How we work

APF is an NVIDIA-owned project. Planning, prioritization, and most development happen internally, and changes are published to this repository on a regular cadence. We accept external contributions, but this is not a community-governed project: the NVIDIA maintainers decide what is merged and when, based on fit with the project roadmap.

## What we welcome

Bug reports with reproduction steps, documentation fixes, small bug fixes, and test improvements are the easiest contributions for us to accept. For anything larger (new features, API changes, new integrations), please open an issue describing the proposal first. We will tell you whether it aligns with the roadmap before you invest effort in a pull request.

Use the path that matches your contribution:

- **Bug or focused improvement:** Open or use an issue that describes the
  observable behavior, reproduction evidence, and desired outcome.
- **Documentation correction:** Open a focused pull request and describe what
  changed.
- **Larger feature or design:** Start with an issue, design note, or
  maintainer-approved discussion so that the problem and design can settle
  before implementation.
- **Policy semantics, signing, governance, integration, or supported
  solution:** Confirm the scope with a maintainer before implementation.
- **New backend, adapter, or integration:** Start with a design note that
  explains ownership, supported surface area, compatibility expectations,
  testing, and release impact.

For substantive work, the issue or linked design note should capture the
decision, rationale, placement, accountable maintainer, and validation plan.
Small documentation corrections and low-risk fixes can proceed directly to a
pull request.

## What to expect

We aim to acknowledge new issues and pull requests within 5 business days, but we do not commit to a merge timeline. Pull requests may be declined if they duplicate internal work in progress, conflict with planned direction, or expand scope we are not prepared to maintain. We will say so rather than leave a PR open indefinitely.

## Signing off your work

- We require that all contributors "sign-off" on their commits. This certifies
  that the contribution is your original work, or you have rights to submit it
  under the same license, or a compatible license.

  - Any contribution which contains commits that are not signed off will not
    be accepted.

- To sign off on a commit, use the `--signoff` (or `-s`) option when
  committing your changes:

  ```bash
  git commit -s -m "feat(apf): add policy bundle validation"
  ```

  This appends the following to your commit message:

  ```text
  Signed-off-by: Your Name <your@email.com>
  ```

- The first time you open a pull request, the DCO Assistant asks you to sign
  the DCO. Post the comment it gives you on the pull request.

- Full text of the [DCO](https://developercertificate.org/), also in the
  [DCO](DCO) file:

  ```text
  Developer Certificate of Origin
  Version 1.1

  Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

  Everyone is permitted to copy and distribute verbatim copies of this
  license document, but changing it is not allowed.


  Developer's Certificate of Origin 1.1

  By making a contribution to this project, I certify that:

  (a) The contribution was created in whole or in part by me and I
      have the right to submit it under the open source license
      indicated in the file; or

  (b) The contribution is based upon previous work that, to the best
      of my knowledge, is covered under an appropriate open source
      license and I have the right under that license to submit that
      work with modifications, whether created in whole or in part
      by me, under the same open source license (unless I am
      permitted to submit under a different license), as indicated
      in the file; or

  (c) The contribution was provided directly to me by some other
      person who certified (a), (b) or (c) and I have not modified
      it.

  (d) I understand and agree that this project and the contribution
      are public and that a record of the contribution (including all
      personal information I submit with it, including my sign-off) is
      maintained indefinitely and may be redistributed consistent with
      this project or the open source license(s) involved.
  ```

## Code review and CI

Every change, internal or external, goes through pull request review by an NVIDIA maintainer. CI on pull requests from forks is triggered by a maintainer after an initial review.

## How to contribute

Search open issues and pull requests before proposing new work. Start with an
existing accepted issue when possible.

1. Create a topic branch or fork.
2. Make one focused change and add tests where applicable.
3. Sign off every commit with `git commit -s`.
4. Use a concise commit message with an applicable prefix, for example:

   ```text
   feat(apf): add policy bundle validation
   fix(policy-gateway): reject expired signatures
   docs(apf): document local verification commands
   test(policy-engine): cover deny decision precedence
   ```

   Common types include `feat`, `fix`, `docs`, `test`, `refactor`, `build`, and
   `ci`.
5. Open a pull request against the default branch. Explain the
   motivation, implementation, and verification performed.
6. Ensure automated checks pass.
7. Address maintainer review feedback.

Do not push directly to the default branch.

## Development setup

Install the basic tools used by the APF repository:

```bash
# Rust: rustup reads rust-toolchain.toml and installs the pinned toolchain.
rustup show

# Everything else is pinned in mise.toml and mise.lock (https://mise.jdx.dev):
# buf, protoc, Python, cargo-deny and cargo-nextest.
mise trust
mise install --locked

# Build once to verify the local environment.
cargo build
```

`mise.toml` and `mise.lock` are the source of truth for tool versions, and
`tasks/*.toml` defines the repository checks; `mise tasks ls` lists them.

## Tests and linting

Read [AGENTS.md](AGENTS.md) before changing code or wire contracts. For a
normal code change, run the applicable repository checks:

```bash
mise run ci              # every check CI runs on a pull request
mise run lint            # cargo fmt --check and cargo clippy -D warnings
mise run test            # cargo nextest run
mise run dag-guard       # crate dependency DAG
mise run contracts:lint  # buf lint contracts/
```

For documentation-only changes, run the documentation checks below instead,
and state that no code tests were required.

## Documentation

The user documentation lives in `docs/` as Fern MDX pages, and the navigation
is defined in `docs/index.yml`. The Fern site configuration is in `fern/`.

- Follow the writing conventions, page structure, and validation steps in
  [docs/CONTRIBUTING.mdx](docs/CONTRIBUTING.mdx).
- If your change affects user-facing behavior, update the affected pages in
  the same pull request.
- Validate the docs with `mise run docs`, and preview them with
  `mise run docs:serve`. Both tasks need mise and Node.js. Refer to
  [fern/README.md](fern/README.md).

## Project layout

```text
apf/
|-- contracts/  # Protobuf and interface contracts
|-- crates/     # Rust workspace crates
|-- deploy/     # Deployment assets
|-- docs/       # Documentation pages (Fern MDX)
|-- e2e/        # End-to-end verification harness
|-- examples/   # Runnable examples and sample policy assets
|-- fern/       # Fern documentation site configuration
|-- scripts/    # Repository scripts
`-- xtask/      # Repository automation and validation helpers
```

`AGENTS.md` documents APF's dependency DAG rules, signing invariants, wire
contract rules, coding conventions, and verification commands for contributors
and automated agents.

## Pull request checklist

Before requesting review, confirm:

- [ ] The change is scoped to one clear problem or feature.
- [ ] Substantive product, architecture, policy, security, integration, or
      supported-surface work has maintainer-confirmed scope.
- [ ] Public behavior, policy semantics, and wire contracts are documented when
      they change.
- [ ] Generated files were produced by the documented generator or command.
- [ ] Tests were added or updated for behavior changes.
- [ ] Local verification commands were run, or skipped checks are explained.
- [ ] CI is passing.
- [ ] No secrets, tokens, internal-only credentials, private customer data, or
      internal-only dependencies are included.
- [ ] The pull request description explains the change well enough for a
      reviewer to evaluate it without reading an agent transcript.
- [ ] Every commit is signed off with `git commit -s`.

## Automated AI and agent-assisted changes

AI tools and agents may help contributors explore the repository, generate
code, run checks, and iterate on a fix. The contributor remains responsible for
the final change.

Do not submit code, policy behavior, or generated output that you cannot
explain. If an automated agent materially contributed to the change, state that
in the pull request description and include the verification commands that were
run.

Agents working in this repository must follow [AGENTS.md](AGENTS.md). Agent
output does not replace maintainer approval, contributor understanding,
security review, or IP review.

## Copyright headers

Every source file carries an SPDX header:

```text
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
```

Python and shell scripts and Dockerfiles use `#` in place of `//`. Helm
`.tpl` templates hold the two lines in a template comment that renders no
output:

```text
{{- /*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */ -}}
```

Documentation pages carry the same header as YAML comments in their
frontmatter. Refer to [docs/CONTRIBUTING.mdx](docs/CONTRIBUTING.mdx).

You do not need to maintain the year by hand. Run `pre-commit install` once
after cloning; the `verify-copyright` hook fixes headers on any file you
change:

- A new file receives the current year.
- An existing file edited in its creation year keeps a single year.
- An existing file edited in a later year receives a range from its original
  year to the current year, such as `2024-2026`.

The hook and CI require the last year in the header to be greater than or
equal to the year of the file's latest commit. If you skip pre-commit, CI
flags missing or stale headers. Fix them locally and push the result:

```bash
pre-commit run verify-copyright --all-files
```

The DCO sign-off certifies that you have the right to submit your
contribution. It does not transfer copyright. Keep existing copyright and
license notices, including those of other contributors and upstream projects.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
