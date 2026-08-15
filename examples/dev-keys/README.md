# dev-keys — Ed25519 signing key for in-tree fixtures

**DEV/CI USE ONLY.** This key lets the in-tree demo bundle
(`examples/demo-bundle/`) be a real signed bundle that `policy-service`
accepts on a fresh checkout with no extra setup.

Key ID: **`apf-dev`** (matches filename stem, used in `APF_DOCUMENT_KEY_ID`
and `--key-id` when signing bundles).

| File | Tracked? | What it is |
|---|---|---|
| `apf-dev.seed` | **yes** | Ed25519 signing seed (`ed25519:<base64>` format). Named `.seed` not `.key` so it is not caught by push rules matching `\.(pem\|key)$`. |
| `apf-dev.pub` | yes | Matching verifying key loaded by the daemon as trust root `apf-dev`. |
| `http-bearer-token.dev` | yes | Fixed dev-only bearer token for `apf-policy-service`'s optional HTTP surface (`APF_HTTP_BEARER_TOKEN_FILE` in `deploy/docker/docker-compose.yml`). Unrelated to bundle signing — the service requires *some* token file whenever `APF_HTTP_ADDR` is set, this is that file for the dev stack. |

## Why the private key is committed

This key has zero security value — it is not a signing-service key, not used in production,
and any signature it produces conveys no enterprise trust. Committing it means
`mise run dev-native`, `docker compose up`, and all bundle-related tests work on
a fresh clone without any setup step.

## Re-signing after policy changes

```bash
# From repo root:
mise run sign-bundle
```

Or manually:

```bash
./target/release/apf-compile genfixture \
    --template examples/demo-bundle/demo-bundle.template.yaml \
    --members-dir examples/demo-bundle \
    --sign-key examples/dev-keys/apf-dev.seed \
    --key-id apf-dev \
    --output examples/demo-bundle/demo-bundle.yaml
```

Commit the updated `demo-bundle.yaml` alongside any template or member changes.

## Production

Use a signing service. Production signing keys live in the signing service, not here.
