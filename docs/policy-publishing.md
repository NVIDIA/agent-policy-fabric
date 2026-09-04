# APF Bundle Publishing Guide

This document describes one mechanism for policy bundle creation and publishing: a GitOps flow where policy originates in Git, is compiled and signed on merge, and published to Artifactory. Any mechanism that produces a signed bundle and publishes it to Artifactory is compatible with the downstream pipeline — GitOps is a convention, not a requirement. For the YAML document schemas and Cedar evaluation model, see [policy-model.md](policy-model.md).

---

## 1. Repository Structure

All policy documents live in a single repository. Teams contribute to the bundles they own by opening pull requests against the relevant bundle directory. There is no cross-repo aggregation step — the repository is the single source of truth for all bundles.

A conventional layout organizes documents by bundle:

```
policy-repo/
  bundles/
    <bundle-name>/
      rules/
      annotators/
      effects/
      findings/
      sandbox/
```

Each bundle directory compiles independently. Teams contribute to the bundles they are responsible for; changes go through standard MR review before merge.

## 2. Compilation and Signing

When a pull request merges to the main branch, CI identifies which bundles were affected and runs `apf-compile` for each:

1. Parses all policy documents in the bundle directory
2. Validates each document
3. Runs the full compilation pipeline:
   - Frontend parsing → IR lowering → substrate projections
   - Emits `PolicySet` (`apf.policy.v1/default`), `ProviderProfileSet` (`openshell.provider-profile.v1/default`), and `SandboxPolicy` (`openshell.sandbox.v1/default`) surface documents
4. Signs the compiled `PolicyBundle` using `BundleSigner` (Ed25519 or an org-specific private backend)

The signing key is stored in CI's secret manager and is never embedded in Git or in the artifact.

## 3. Publication to Artifactory

CI publishes the signed bundle to Artifactory with a version derived from the commit or pipeline run:

```
  Merge to main
  │  CI compiles affected bundles
  │  signs each → PolicyBundle
  │  publishes → Artifactory: apf-policy-bundles/<bundle-name>/<version>.bundle
  ▼
  Artifactory ── HttpBundleSource ──▶ apf-policy-service ──▶ GetDocument responses
```

`apf-policy-service` polls Artifactory for the latest signed bundle on a configurable interval. A new version in Artifactory triggers the gateway's digest watcher and initiates a full hot-swap — no restart required.

## 4. Evolution with a Dedicated Cloud PAP

The GitOps model described above is the current supported path. As `apf-policy-service` evolves into a dedicated cloud-hosted PAP (see [architecture.md §5.2](architecture.md)), it will be the natural home for bundling, signing, and publication as first-class service APIs:

- Teams submit policy documents to the PAP directly, or via lightweight CI steps that no longer need to run `apf-compile` themselves
- The PAP handles aggregation, compilation, signing, and versioning internally
- Artifactory remains the distribution layer, but publication is driven by the PAP rather than CI

In that model the CI pipeline becomes a validation gate — lint, dry-run compile, policy review — rather than the authority for producing and publishing bundles. The contract for downstream gateways remains unchanged; only the origin of the signed artifact in Artifactory changes.

## 5. End-to-End Flow

```
  Security team
  │  PR: annotators/prompt-injection-detector.yaml   ← detects adversarial prompt patterns
  │      rules/security-content-gate.yaml            ← forbid on detection, escalate on ambiguous
  │      findings/prompt-injection.yaml
  │
  Agent owner (e.g. coding assistant team)
  │  PR: rules/github-grants.yaml                    ← capability grants for their agent's tools
  │      effects/redact-code-secrets.yaml            ← redact secrets before they leave sandbox
  │
  Platform team
  │  PR: sandbox/default-policy.yaml                 ← network perimeter for all sandboxes
  │
  │  PR review → merge to main
  ▼
  CI pipeline
  │  detect affected bundles
  │  apf-compile → PolicyBundle (signed)
  │  publish versioned artifact → Artifactory
  ▼
  apf-policy-service
  │  HttpBundleSource polls Artifactory
  │  validates signature, refreshes PolicySource
  ▼
  apf-policy-gateway
  │  digest watcher detects change
  │  fetch PolicySet → rebuild CedarEvaluator → hot-swap (lock-free)
  ▼
  Active policy updated — no restart required
```

Each team contributes to the document kinds they own. The security team's annotator and rule are available to all other rules in the same bundle — a `prompt-injection-detector` annotator written once is automatically visible to the coding assistant team's capability rules without any coordination between the two teams.

## 6. Distribution and Hot-Swap

`verify_bundle()` (signature, manifest hashes, expiry, `runtime_compatibility`, monotonic
counter) runs once, inside `apf-policy-service`, when it ingests a bundle from its upstream
source — not on every gateway poll. `apf-policy-gateway`'s hot-swap path (`digest_watcher` →
`GetDocument` → decode → build evaluator → swap) does not re-verify the bundle signature or
the `provenance_token` JWT; it trusts the `GetDocument` response over the local UDS transport.

```
Upstream Source            apf-policy-service              apf-policy-gateway
      │                             │                               │
      │◀────── fetch bundle ────────│                               │
      │─────── bundle bytes ───────▶│                               │
      │                             │ verify_bundle()               │
      │                             │ • BundleVerifier (sig)        │
      │                             │ • manifest hashes             │
      │                             │ • expiry                      │
      │                             │ • runtime_compatibility       │
      │                             │ • monotonic counter           │
      │                             │ store in PolicySource         │
      │                             │                               │
      │                             │◀──── GetDocument (poll) ──────│ digest_watcher
      │                             │                               │
      │                             │ digest unchanged?             │
      │                             │───────── 304 / same ─────────▶│ no-op
      │                             │                               │
      │                             │ digest changed:               │
      │                             │───── GetDocumentResponse ────▶│
      │                             │ body + provenance_token       │
      │                             │ (not re-verified here)        │
      │                             │                               │
      │                             │                               │ decode PolicySet
      │                             │                               │ build CedarEvaluator
      │                             │                               │ arc-swap (lock-free)
      │                             │                               │
      │                             │                               │ ✓ new bundle live
```

The gateway keeps the last known good evaluator if a fetch fails; a bad bundle never
replaces a working one.
