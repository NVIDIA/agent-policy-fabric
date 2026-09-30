# OpenShell protocol compatibility

APF pins generated OpenShell bindings in `crates/apf-proto/build.rs`. A gateway
starting successfully does not prove its extension protocol matches APF.

This revision selects OpenShell `v0.1.2`, source
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. The `proto/` tree is identical to
`v0.1.0`. The previous APF pin was `e38d7254e6099a42d6b80329b8e4ef6f0817931f`
(`0.0.117-dev.204`).

## Extension protocol negotiation

OpenShell 0.1.0 requires every gateway interceptor and supervisor middleware to
exchange `openshell.extension.v1.PeerMetadata` during `Describe`. The gateway
sends its metadata in `DescribeRequest.gateway` /
`MiddlewareDescribeRequest.gateway`; the manifest must return
`InterceptorManifest.extension` / `MiddlewareManifest.extension`. A gateway
that receives a manifest without that field, a different protocol major, or an
unmet required capability refuses to start.

`apf_openshell_auth::protocol` advertises protocol `1.0` and one required
capability per family (`openshell.gateway-interceptor.contract`,
`openshell.supervisor-middleware.contract`). Both adapters validate the
gateway's metadata and fail `Describe` with `FAILED_PRECONDITION` when it is
missing or incompatible, so a mismatched gateway cannot register APF.

Between the previous pin and `v0.1.2`, `sandbox.proto` renamed
`UpdateConfigRequest.name` to `sandbox`; the refresher uses the new field. No
other wire shape used by APF changed.

## Provider snapshot enums

Since `dev.204`, endpoint TLS, enforcement and access travel as protobuf enums
at the field numbers that previously carried strings; a snapshot that sends
strings is rejected with `NetworkEndpoint.enforcement: invalid wire type:
LengthDelimited (expected Varint)`. The OpenShell adapters emit those enums,
reject unknown modes, convert APF credential seconds to optional protobuf
durations, and retain the operator's middleware timeout when no override is
specified. The sandbox refresher uses opaque page tokens and explicit
default-workspace scope, preserving optimistic concurrency and refusing
cross-workspace updates. Invalid provider documents fail the whole snapshot
instead of publishing a silently incomplete profile set.

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
