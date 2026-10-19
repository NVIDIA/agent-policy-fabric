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

## First-time contributors

APF uses a vouch system. Maintainers and collaborators with write access can
open pull requests directly. Everyone else must be vouched first:

1. Open a [Vouch Request](https://github.com/NVIDIA/agent-policy-fabric/discussions/new?category=vouch-request)
   discussion describing what you want to work on and why. Write it yourself;
   requests that read like LLM output are denied.
2. A maintainer comments `/vouch`. The `vouch-command` workflow adds your
   username to `.github/VOUCHED.td` on the `vouched` branch.
3. Open your pull request. A pull request from an unvouched author is closed
   automatically with instructions. Maintainers can also denounce a user by
   adding `-username` to `VOUCHED.td`.

## Developer Certificate of Origin

All contributions must be signed off under the [DCO](https://developercertificate.org/). Add `-s` to your `git commit` to certify that you have the right to submit the work under the project's Apache-2.0 license. The `DCO` workflow fails any pull request containing a commit without a matching `Signed-off-by` trailer. Fix a branch with `git rebase --signoff <base>` and a force-push. Unsigned commits cannot be merged.

## Code review and CI

Every change, internal or external, goes through pull request review by an NVIDIA maintainer.

CI runs on NVIDIA self-hosted runners, gated by
[copy-pr-bot](https://github.com/nv-gha-runners/docs/blob/main/docs/platform/apps/copy-pr-bot/index.md).
It does not trigger on `pull_request` events; it triggers on pushes to
`pull-request/<N>` branches that the bot creates.

- **Trusted changes** (an NVIDIA org member, and every commit cryptographically
  signed) are copied automatically, and again on each push. Sign commits with
  [SSH commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification),
  which is separate from the DCO `-s` sign-off. If you push an unsigned commit,
  rebase to sign it and force-push.
- **Untrusted changes** (an external author, an unsigned commit, or 250 or more
  commits) are not run until a maintainer reviews the whole diff and comments
  `/ok to test <full 40-character SHA of the latest commit>`. An abbreviated or
  stale SHA is rejected, and every later push needs a new comment.
- Draft pull requests are not synced automatically. A maintainer or you can
  comment `/ok to test` to run CI on one.

Maintainers: before approving, check the diff for changes to
`.github/workflows/`, `tasks/`, `scripts/`, `xtask/`, `build.rs` files, and
dependency manifests. These all run code on our runners. The pushed
`pull-request/*` branch is deleted when the pull request closes. To stop
fetching these branches locally, run
`git config --global --add remote.origin.fetch '^refs/heads/pull-request/*'`.

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

## Merging

Maintainers merge with **rebase merge** or **squash**. Use rebase merge when a
pull request has several commits that each stand alone, so every commit and its
`Signed-off-by` is kept. Use squash for a single logical change with noisy
fix-up commits; the squash commit takes the pull request title, so it must
follow the commit format above. Merge commits are disabled.

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

For documentation-only changes, state that no code tests were required.

## Project layout

```text
apf/
|-- contracts/  # Protobuf and interface contracts
|-- crates/     # Rust workspace crates
|-- deploy/     # Deployment assets
|-- docs/       # Design and architecture documentation
|-- examples/   # Runnable examples and sample policy assets
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

Contributed code is copyrighted to NVIDIA under the DCO terms. Do not add a
separate personal copyright line.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
