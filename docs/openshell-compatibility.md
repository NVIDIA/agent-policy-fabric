# OpenShell protocol compatibility

APF pins generated OpenShell bindings in `crates/apf-proto/build.rs`. A gateway
starting successfully does not prove its extension protocol matches APF.

This revision selects OpenShell `0.0.117-dev.204+ge38d7254e`, source
`e38d7254e6099a42d6b80329b8e4ef6f0817931f`. The previous APF pin was
`8d67250a5d17348eb96c4fa46226b06d8041f2ba`.

The old APF provider snapshot sends endpoint TLS, enforcement and access as
strings. Dev.204 expects enums at the same protobuf field numbers and rejects
those responses with `NetworkEndpoint.enforcement: invalid wire type:
LengthDelimited (expected Varint)`.

The OpenShell adapters now emit those enums, reject unknown modes, convert APF
credential seconds to optional protobuf durations, and retain the operator's
middleware timeout when no override is specified. The sandbox refresher uses
opaque page tokens and explicit default-workspace scope, preserving optimistic
concurrency and refusing cross-workspace updates. Invalid provider documents
fail the whole snapshot instead of publishing a silently incomplete profile set.

APF policy authoring/IR contracts, signed bundles, authentication and counter
storage are unchanged. Omitted enforcement retains OpenShell's existing audit
default; it is not a fallback for invalid values. Uninspected credentials remain
disabled. The two deprecated TLS spellings are passed as their corresponding
upstream enum values. New credential grant modes and response middleware hooks
are not enabled by this change.

## Coordinated rollout

Ubuntu's previous OpenShell dev.192 pin (`50c5cf8ed0423f545fee7e0ccc7e7699eec9e290`)
still uses string endpoint fields. **This APF build is not a drop-in replacement
for that stack.** Update the Ubuntu OpenShell package, supervisor and sandbox
pins together with compatible APF binaries. Keep existing deployments on their
previous matched versions until the coordinated candidate passes qualification.
The Mac candidate uses dev.204 and requires rebuilt APF ARM64 images.

Protocol regression coverage includes exact enum wire bytes, invalid mode
rejection at both projection paths, profile snapshot failure, credential duration
bounds, scoped refresh, and existing admission/authentication/middleware tests.
Local tests and local images do not constitute managed-device qualification or
an approval to publish release artifacts.
