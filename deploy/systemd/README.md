# systemd deployment

Runs `apf-policy-service` and `apf-policy-gateway` as the unprivileged `apf`
system account, co-located on one host (the currently supported topology —
see `docs/architecture.md`). Read **`SECURITY.md` before deploying** — it
covers the access-control, interface-lockdown, and process-lockdown
requirements this unit set implements and cannot fully enforce on its own
(host firewall, polkit, sudoers, and file-integrity monitoring live outside
what a `.service` file can express).

## Layout

```text
/etc/apf/policy-service.env        non-secret apf-policy-service settings
/etc/apf/policy-gateway.env        non-secret apf-policy-gateway settings
/etc/apf/document-signing-key      root-readable Ed25519 seed (LoadCredential)
/etc/apf/http-bearer-token         optional — only if APF_HTTP_ADDR is enabled
/etc/apf/bundle/bundle.yaml        signed policy bundle
/etc/apf/trust-roots/*.pub         trust root keys for bundle verification
/etc/apf/openshell-interceptor-auth.toml   trust profile verifying the interceptor's OpenShell callers
/etc/apf/openshell-middleware-auth.toml    trust profile verifying the middleware's OpenShell callers
/etc/apf/tls/interceptor-cert.pem  TLS cert apf-policy-gateway presents on the interceptor surface
/etc/apf/tls/interceptor-key.pem   matching private key (LoadCredential), required whenever
                                   APF_OPENSHELL_INTERCEPTOR_ADDR is set
/etc/apf/tls/middleware-cert.pem   TLS cert apf-policy-gateway presents on the middleware surface
/etc/apf/tls/middleware-key.pem    matching private key (LoadCredential), required whenever
                                   APF_OPENSHELL_MIDDLEWARE_ADDR is set
/var/lib/apf/policy-service/       policy-service state (counter store)
/var/lib/apf/policy-gateway/       policy-gateway state
/run/apf/policy-service.sock       shared UDS, control plane
/run/apf/policy-gateway.sock       gateway's own UDS (EvaluationService)
```

`RuntimeDirectory=apf` in both units maps to the same `/run/apf`; systemd
reference-counts it so starting/stopping one service doesn't remove the
other's socket. Both daemons run as the same `apf` UID because each binds
its own UDS at mode `0600` (owner-only) — see `apf.sysusers.conf` and
`SECURITY.md` for why that rules out separate accounts today.

## Install

Build the release binaries from the repo root:

```fish
cargo build --release -p apf-policy-service -p apf-policy-gateway
```

Install the account, units, and environment files:

```fish
sudo install -D -m 0755 target/release/apf-policy-service /usr/local/bin/apf-policy-service
sudo install -D -m 0755 target/release/apf-policy-gateway /usr/local/bin/apf-policy-gateway
sudo install -D -m 0644 deploy/systemd/apf.sysusers.conf /etc/sysusers.d/apf.conf
sudo systemd-sysusers /etc/sysusers.d/apf.conf
sudo install -D -m 0644 deploy/systemd/apf-policy-service.service /etc/systemd/system/apf-policy-service.service
sudo install -D -m 0644 deploy/systemd/apf-policy-gateway.service /etc/systemd/system/apf-policy-gateway.service
sudo install -o root -g root -m 0644 deploy/systemd/apf-policy-service.env /etc/apf/policy-service.env
sudo install -o root -g root -m 0644 deploy/systemd/apf-policy-gateway.env /etc/apf/policy-gateway.env
sudo install -D -m 0644 deploy/systemd/49-apf-service-lockdown.rules /etc/polkit-1/rules.d/49-apf-service-lockdown.rules
```

Then, following the ownership/mode table in `SECURITY.md`, install:

- `/etc/apf/bundle/bundle.yaml` — the signed policy bundle
- `/etc/apf/trust-roots/*.pub` — trust root keys
- `/etc/apf/document-signing-key` — Ed25519 seed, `root:root 0600`
- `/etc/apf/openshell-interceptor-auth.toml`/`openshell-middleware-auth.toml`
  — trust profiles, `root:apf 0640`, one per surface, only if that surface's
  `_ADDR` is enabled
- `/etc/apf/tls/{interceptor,middleware}-cert.pem` — TLS certificates,
  `root:apf 0640`, only if that surface's `_ADDR` is enabled
- `/etc/apf/tls/{interceptor,middleware}-key.pem` — matching private keys,
  `root:root 0600`, only if that surface's `_ADDR` is enabled — see
  `SECURITY.md` §2 for the full caller-auth requirement

Validate and start:

```fish
sudo systemd-analyze verify /etc/systemd/system/apf-policy-service.service
sudo systemd-analyze verify /etc/systemd/system/apf-policy-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now apf-policy-service.service
sudo systemctl enable --now apf-policy-gateway.service
```

Both daemons read their configuration once at startup; there is no reload
command. A policy-bundle change or config edit requires restarting
`apf-policy-service` (the gateway hot-swaps its Cedar evaluator on bundle
digest change without restarting). Restart through the deploy pipeline
only — see `SECURITY.md`.

## Enabling the OpenShell seams

`APF_OPENSHELL_INTERCEPTOR_ADDR` and `APF_OPENSHELL_MIDDLEWARE_ADDR` are
active by default in `apf-policy-gateway.env` for this deploy's assumed
co-located topology. Confirm `APF_JWKS_URL` is reachable first — the
gateway refuses to start the interceptor surface without a working JWKS
verifying key for policy-service's own provenance tokens.

Setting either address also requires that surface's trust file and TLS
certificate variables in the same file
(`APF_OPENSHELL_INTERCEPTOR_AUTH_TRUST_FILE`/`_TLS_CERT_FILE`, or the
`MIDDLEWARE` equivalents), plus the matching `/etc/apf/tls/*-key.pem`
installed and its paired `LoadCredential` line already present in
`apf-policy-gateway.service` — the gateway refuses to start a surface
without all three of that surface's files. This is what lets
`apf-policy-gateway` verify the bearer token OpenShell attaches to its
calls, rather than trusting the loopback bind alone. The two surfaces are
independent: enabling one doesn't require the other.

## Enabling the HTTP surface

`APF_HTTP_ADDR` is commented out by default in `apf-policy-service.env` —
leave it that way unless something genuinely needs it. `apf-policy-gateway`
doesn't: `PolicyService` already exposes a `Health` RPC over the same UDS
socket used for `GetDocument`, so anything running as `apf` has a liveness
check without HTTP. The two things HTTP actually adds are JWKS (no UDS
equivalent exists) and reachability for a caller that isn't UID `apf` and
has no gRPC client. If you do enable it, uncomment
`LoadCredential=http-bearer-token:...` in `apf-policy-service.service` too
and install the paired secret:

```fish
openssl rand -hex 32 | sudo tee /etc/apf/http-bearer-token >/dev/null
sudo chmod 0600 /etc/apf/http-bearer-token
sudo chown root:root /etc/apf/http-bearer-token
```

The daemon refuses to start with `APF_HTTP_ADDR` set and no token file —
there's no unauthenticated fallback. `/healthz` and `/readyz` stay
reachable without the token regardless; only `/v1/documents` and
`/v1/refresh` require it.
