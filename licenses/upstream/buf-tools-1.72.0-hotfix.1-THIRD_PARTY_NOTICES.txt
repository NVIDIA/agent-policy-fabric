# Third-Party Notices

## License of this crate vs. Buf

This crate's own source code (the contents of the `.crate` archive published to
crates.io: `Cargo.toml`, `build.rs`, `build_support/**`, `src/**`) is licensed
under the MIT license. See [`LICENSE`](LICENSE).

The crate does not redistribute Buf or any Buf-derived source. It contains only
the Rust glue you need to:

1. resolve your compilation target,
2. fetch upstream Buf release artifacts at build time, directly from
   `bufbuild/buf` GitHub releases on your machine, and
3. verify those downloads via `sha256.txt` + `sha256.txt.minisig` before use.

## Buf CLI (downloaded at build time)

When you build against this crate, `build.rs` downloads the following
unmodified third-party binary artifacts from GitHub releases:

- `buf-<TARGET>` (and `.exe` on Windows)
- `protoc-gen-buf-breaking-<TARGET>`
- `protoc-gen-buf-lint-<TARGET>`

Provenance:

- Upstream project: <https://github.com/bufbuild/buf>
- Upstream license: Apache License 2.0
  (<https://github.com/bufbuild/buf/blob/main/LICENSE>)
- Copyright: Buf Technologies, Inc. and contributors (per upstream notices).

These artifacts are cached on your filesystem (under `$BUF_RS_CACHE_DIR` or the
platform cache directory). The Apache-2.0 terms governing those artifacts apply
to your local copies; this crate neither modifies nor redistributes them.

## Optional upstream source

When you set `BUF_RS_INCLUDE_SOURCE=1` at build time, `build.rs` additionally
downloads the upstream tagged source archive
(`archive/refs/tags/v<X.Y.Z>.tar.gz`) from `bufbuild/buf` and extracts it into
the per-version cache slot for inspection or audit. That source is Apache-2.0
and remains the property of its respective copyright holders. As with the
binaries, this crate does not include or redistribute it.

## Trademark

"Buf" is referenced descriptively to identify the upstream tooling this crate
locates. Use of the name does not imply endorsement by, or affiliation with,
Buf Technologies, Inc.
