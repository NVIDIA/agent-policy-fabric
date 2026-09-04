# APF Policy Authoring Schemas

This directory contains JSON Schemas for APF policy documents that are authored
directly:

- `policy-bundle.v1alpha1.schema.json`
- `sandbox-policy.v1alpha1.schema.json`
- `provider.v1alpha1.schema.json`
- `policy-rule.v1alpha1.schema.json`
- `policy-annotator.v1alpha1.schema.json`
- `policy-effect.v1alpha1.schema.json`
- `policy-finding.v1alpha1.schema.json`

Sandbox and provider endpoint constraints follow the OpenShell sandbox/provider
configuration accepted by the runtime. Other fields follow the APF compiler and
bundle parsers.
