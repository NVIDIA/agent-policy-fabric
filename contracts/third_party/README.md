# Vendored third-party protobuf sources

The directories here are verbatim exports of protobuf sources from other
projects, pinned to a specific revision in [`pins.toml`](pins.toml). They let
`cargo build` and `buf lint contracts/` work from a fresh clone with no network
access and no `buf` installation.

| Directory | Source | Used by |
|---|---|---|
| `openshell/proto/` | [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell), `proto/` | `crates/apf-proto/build.rs` compiles the sandbox, extension, gateway-interceptor, supervisor-middleware, datamodel and OpenShell service definitions |
| `yaml-sigil/proto/` | [NVIDIA/yaml-sigil-spec](https://github.com/NVIDIA/yaml-sigil-spec), `proto/` | `contracts/buf.yaml` lists it as a module; `signature.proto` imports `yaml_sigil/v1alpha1/yaml_sigil.proto` |

Both sources are licensed under Apache-2.0 and carry their own SPDX headers,
which are kept as published; the repository's header check skips this
directory.

## Refreshing

1. Change the `ref` in `pins.toml`.
2. Run `cargo xtask vendor-protos` (needs `buf`, pinned in `mise.toml`). The
   task re-exports every pin and replaces the directory contents.
3. Build and test, then commit the pin change together with the exported files.

`cargo xtask vendor-protos --check` re-exports into a temporary directory and
fails if the tree differs from the pins; CI runs it so the two cannot drift.
