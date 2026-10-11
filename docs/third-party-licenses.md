<!-- rumdl-disable MD013 -->

# Third-party licenses and attribution

[THIRD_PARTY_LICENSES.txt](../THIRD_PARTY_LICENSES.txt) lists every external crate version in `Cargo.lock`, its upstream license expression, APF's selected license, copyright or author attribution, and the full upstream license and notice texts. It includes optional, build, development and platform-specific dependencies, so its contents cover more than any single APF binary.

## r-efi license selection

APF selects MIT for both locked versions of `r-efi`. Upstream offers `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; these are alternative grants. APF uses the MIT grant, so LGPL static-linking conditions do not apply to this use of `r-efi`. No replacement is required.

The published `AUTHORS` files for [r-efi 5.3.0](https://github.com/r-efi/r-efi/blob/v5.3.0/AUTHORS) and [r-efi 6.0.0](https://github.com/r-efi/r-efi/blob/v6.0.0/AUTHORS) contain the MIT permission text and identify Red Hat, Microsoft, and David Rheinsberg as copyright holders. The generated notice retains the MIT grant and their statements. `getrandom` declares these dependencies for its UEFI RNG backend; their presence in the lockfile does not imply that Linux binaries contain them.

## Regeneration and verification

Run from the repository root with Cargo and Python 3.11 or newer. No Python packages or license-scanner installation are required.

```fish
uv run --no-project python scripts/third_party_licenses.py
uv run --no-project python scripts/third_party_licenses.py --check --offline
uv run --no-project python -B -m unittest discover -s scripts -p 'test_third_party_licenses.py'
```

The first command lets Cargo download missing locked sources. `--offline` uses already fetched sources. The generator compares Cargo metadata with every external lockfile entry and stops if any are missing. It also stops on an unreviewed license expression, missing license documents, missing attribution, or a changed supplemental source checksum. CI runs the freshness check on each pipeline.

[`licenses/selections.json`](../licenses/selections.json) records explicit choices for the upstream expressions. It prefers MIT where available and preserves required `AND` terms. A new expression requires review before generation can proceed. Existing dependencies with other licenses retain those licenses; this file does not grant new usage rights or replace open-source review. In particular, `foldhash` remains Zlib. The MIT selection for `r-efi` is checked separately and cannot silently change to LGPL.

The generator copies license, copyright, author and notice documents from the published crate sources, including notices for bundled code. Identical text shares one block in the output; each component retains its own source references. Missing published license files are supplemented from pinned upstream revisions under [`licenses/upstream/`](../licenses/upstream/), with URLs, checksums and extraction details recorded in `provenance.json`.

Some upstream projects publish license terms without a separate copyright statement. The notice identifies their published authors or project contributors and labels that attribution explicitly. It does not turn author metadata into a copyright claim. Version-specific project attribution and checksums for its source evidence are recorded in [`licenses/attribution.json`](../licenses/attribution.json).

## Dependency license check

APF allows MIT and Apache-2.0 for every crate it builds. Any other license must be granted to a named crate by an exception in [`deny.toml`](../deny.toml). That covers a crate licensed only under another license (`foldhash` is Zlib) and a crate whose license adds a required term (`ring` is `Apache-2.0 AND ISC`, so its exception grants ISC to `ring` and to no other crate). The `lint:cargo-deny-licenses` CI job enforces this by running `cargo-deny --locked check licenses -D no-license-field` in every pull request pipeline. GitLab requires a successful pipeline before a pull request can merge, so a failed check blocks the merge. Maintainers can still push directly to `main`; the pipeline that runs after such a push reports a violation but does not prevent it.

The check fails when a new crate needs a license outside MIT and Apache-2.0, when an excepted crate adds a license that its exception does not list, when a crate omits the `license` field, and when an exception is no longer needed. An exception applies to every version and source of the crate name it lists. cargo-deny does not report an exception that lists more licenses than its crate needs, so reviewers must check that each exception names only licenses the crate declares. Other `deny.toml` keys can also admit a crate, including `[graph]` settings, `[[licenses.clarify]]` and `[licenses.private]`; treat any change to that file as a license decision.

The check covers development and build dependencies, every feature of APF's own crates, dependencies for all target platforms, and APF's workspace crates. It reads Cargo metadata only. The OpenShell protobuf sources that the `apf-proto` build script exports with `buf` and the operating-system packages in container images are outside it; review changes to those as dependency changes too.

This check and `licenses/selections.json` review different things. A selection applies to a license expression: once `ISC` has a selection, a later ISC crate gets a notice without another review. A cargo-deny exception names a crate, so each new crate with another license still needs its own decision. To add such a crate, add an exception that names the crate and only its additional license, add a selection if its expression is new, and regenerate `THIRD_PARTY_LICENSES.txt` in the same pull request. An exception records that decision in the repository; it does not replace open-source review.

`Cargo.lock` also lists crates that no APF build compiles. Most are optional dependencies of third-party crates behind features APF does not enable, such as `iana-time-zone` behind the `clock` feature of `chrono`. cargo-deny skips these crates and checks them once a change adds them to a build. The notice lists them regardless.

Run the check locally with the version that CI pins in `CARGO_DENY_VERSION`, currently 0.20.2. Calling `cargo-deny` directly, as CI does, runs the first copy on `PATH`; `cargo deny` can prefer a different copy in `$CARGO_HOME/bin`.

```fish
cargo install --locked cargo-deny@0.20.2
cargo-deny --version
cargo-deny --locked check licenses -D no-license-field
```

## Vendored protobuf sources

`contracts/third_party/` holds protobuf sources exported from other NVIDIA open-source projects at the revisions pinned in `contracts/third_party/pins.toml` (see its README). They are not Cargo packages, so they do not appear in `THIRD_PARTY_LICENSES.txt`; each file keeps its upstream Apache-2.0 header, and `cargo xtask vendor-protos --check` keeps the tree in step with the pins.

## Distribution

The release build includes `LICENSE` and `THIRD_PARTY_LICENSES.txt` in `dist/`. Binary publishing jobs upload both files beside the binaries in the revision-specific and `latest` directories. Container recipes copy both files into `/usr/share/licenses/apf/`; demo and release targets inherit them.

When distributing a binary outside those jobs, include both files alongside it. Release image preparation exports committed `HEAD`, so commit updated notices before preparing that build context. The notice covers the Rust dependency inventory; operating-system packages in container base images retain their separate distribution notices.
