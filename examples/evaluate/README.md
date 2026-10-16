<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Evaluate requests

`EvaluateRequest` messages in protobuf JSON for
`nvidia.agent_policy_fabric.pdp.v1alpha1.EvaluationService/Evaluate`, the
decision surface the policy gateway serves over its Unix socket. The action is
`resource.class` alone when `verb` is empty, and `<class>::<verb>` when a verb
is given. The MCP tool name sent as the class is the action the OpenShell
middleware produces for the same tool call, so these requests exercise the
grants written for that path. Against `examples/demo-bundle`:

| File | Action | Decision |
| --- | --- | --- |
| `allow.json` | `github_repo_read` | `DECISION_ALLOW` (permitted by `rules/github-grants.yaml`) |
| `deny.json` | `github_repo_write` | `DECISION_DENY` (`no grant for github_repo_write`) |

`deploy/compose/e2e/smoke.sh` sends both through `grpcurl`; see
`deploy/compose/README.md` for the command.
