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

[`licenses/selections.json`](../licenses/selections.json) records explicit choices for the upstream expressions. It prefers MIT where available and preserves required `AND` terms. A new expression requires review before generation can proceed. Existing dependencies with other licenses retain those licenses; this file does not grant new usage rights or replace open-source review. In particular, `option-ext` remains MPL-2.0. The MIT selection for `r-efi` is checked separately and cannot silently change to LGPL.

The generator copies license, copyright, author and notice documents from the published crate sources, including notices for bundled code. Identical text shares one block in the output; each component retains its own source references. Missing published license files are supplemented from pinned upstream revisions under [`licenses/upstream/`](../licenses/upstream/), with URLs, checksums and extraction details recorded in `provenance.json`.

Some upstream projects publish license terms without a separate copyright statement. The notice identifies their published authors or project contributors and labels that attribution explicitly. It does not turn author metadata into a copyright claim. Version-specific project attribution and checksums for its source evidence are recorded in [`licenses/attribution.json`](../licenses/attribution.json).

## Distribution

The release build includes `LICENSE` and `THIRD_PARTY_LICENSES.txt` in `dist/`. Binary publishing jobs upload both files beside the binaries in the revision-specific and `latest` directories. Container recipes copy both files into `/usr/share/licenses/apf/`; demo and release targets inherit them.

When distributing a binary outside those jobs, include both files alongside it. Release image preparation exports committed `HEAD`, so commit updated notices before preparing that build context. The notice covers the Rust dependency inventory; operating-system packages in container base images retain their separate distribution notices.
