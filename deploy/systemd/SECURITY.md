# APF host deployment: security requirements

**Audience:** deployment/platform engineers installing or operating
`apf-policy-service` and `apf-policy-gateway` on a host. This is an
operational checklist — what to configure, what to verify, and why —
not a code walkthrough. It assumes familiarity with the unit files in
`systemd/` but not with the APF codebase itself.

This document is deliberately separate from `systemd/*.service`. Unit files
are packaged and reinstalled by the deploy pipeline; the requirements below
also cover host state (file ownership, firewall, polkit, sudoers, auditd)
that a `.service` file cannot express or that must survive a package
reinstall without being silently reset. Treat this as the checklist a
reviewer signs off against, not documentation of what the units already do.

Scope: `apf-policy-service` + `apf-policy-gateway`, co-located with an
OpenShell gateway/supervisor on one host (the current supported topology —
see `apf/docs/architecture.md`).

## 1. Access controls on OpenShell and APF configuration

Config integrity is the actual trust root here: `apf-policy-service` signs
every projection it serves, but that signature only means "this document
matches what was in the bundle at load time" — it says nothing about
whether the bundle itself was legitimately authored. Anyone who can write
the bundle file or a trust root controls what the sandbox is allowed to
do, signature or not.

Config common to both policy-source modes:

| Path | Owner:Group | Mode | Used by | Purpose |
|---|---|---|---|---|
| `/etc/apf` | `root:apf` | `0750` | both | parent config dir; scopes read access to the `apf` account only |
| `/etc/apf/*.env` | `root:root` | `0644` | both | non-secret runtime settings (socket paths, addrs, log level); checked in review |
| `/etc/apf/document-signing-key` | `root:root` | `0600` | `apf-policy-service` | signing key used to stamp a provenance token on every document it serves, so `apf-policy-gateway` can detect tampering in transit or at rest; never group-readable, delivered as a systemd credential so `apf` never has a direct filesystem path to it |
| `/etc/apf/http-bearer-token` | `root:root` | `0600` | `apf-policy-service` | shared secret gating the sensitive routes on the optional HTTP surface (§2); only needed if that surface is enabled, delivered the same way as the signing key |
| `/etc/apf/openshell-interceptor-auth.toml` | `root:apf` | `0640` | `apf-policy-gateway` | static trust profile (issuer, audience, signing kid, OpenShell's Ed25519 public key) verifying callers on the interceptor surface (§2); not secret — it's public-key material — but must not be group/world writable |
| `/etc/apf/openshell-middleware-auth.toml` | `root:apf` | `0640` | `apf-policy-gateway` | same as above, for the middleware surface; independent trust file — not interchangeable with the interceptor's even though they share a format |
| `/etc/apf/tls/interceptor-cert.pem` | `root:apf` | `0640` | `apf-policy-gateway` | TLS certificate presented to OpenShell on the interceptor surface (§2); not secret, group-readable is fine |
| `/etc/apf/tls/interceptor-key.pem` | `root:root` | `0600` | `apf-policy-gateway` | private key matching the certificate above; delivered as a systemd credential like the signing key, required whenever the interceptor address is set |
| `/etc/apf/tls/middleware-cert.pem` | `root:apf` | `0640` | `apf-policy-gateway` | TLS certificate presented to OpenShell on the middleware surface (§2); not secret, group-readable is fine |
| `/etc/apf/tls/middleware-key.pem` | `root:root` | `0600` | `apf-policy-gateway` | private key matching the certificate above; delivered as a systemd credential like the signing key, required whenever the middleware address is set |
| `/var/lib/apf/policy-service/counter` | `apf:apf` | `0700` | `apf-policy-service` | persistent counter that prevents an older, previously-superseded bundle from being loaded again (anti-rollback) |
| `/var/lib/apf/policy-gateway/**` | `apf:apf` | `0700` | `apf-policy-gateway` | gateway's own state; daemon-owned, not shared with the service |

`apf-policy-service` can load the bundle two ways. They have different
trust models and different config — follow the section that matches your
deployment.

### Policy source: `local` (default)

This is the default this deploy ships with. The rest of this document —
the interface lockdown and process-lockdown requirements below — applies
the same way no matter which policy source is in use; only this section
differs. The bundle is read from disk at startup and on every reload, and
it's checked against the trust-root keys every time — the bundle must
carry a valid signature from a trusted key, or it's rejected. This table
is the entire access-control story for this mode: whoever can write the
bundle file or a trust root controls the policy.

| Path | Owner:Group | Mode | Purpose |
|---|---|---|---|
| `/etc/apf/bundle/` | `root:apf` | `0750` | holds the signed policy bundle |
| `/etc/apf/bundle/bundle.yaml` | `root:apf` | `0640` | the signed policy itself; loaded and compiled at startup, re-read on reload. Writable by root only — this is the actual authorization trust root (see above) |
| `/etc/apf/trust-roots/` | `root:apf` | `0750` | holds the public key(s) that verify the bundle's signature; a directory rather than one file to support key rotation (old and new root coexist during rollover) |
| `/etc/apf/trust-roots/*.pub` | `root:apf` | `0640` | one public key each, the counterpart to whatever private key the offline bundle-signing pipeline uses — verifies the bundle on load, distinct from the signing key in the common table above |

### Policy source: `http`

The bundle is fetched from a configured URL instead of read from disk, so
the `/etc/apf/bundle/` row in the `local`-mode table above doesn't apply —
nothing is written to disk for the bundle itself. `/etc/apf/trust-roots/`
still applies exactly as in `local` mode: every fetched bundle is checked
against the same trust-root keys before it's compiled or served, so that
directory must be populated the same way regardless of policy source.

| Path | Owner:Group | Mode | Purpose |
|---|---|---|---|
| `/etc/apf/bundle-source-token` | `root:root` | `0600` | bearer credential for the bundle source URL; same delivery handling as `document-signing-key` in the common table, never a bare value in the env file |

The URL and the token are still part of the trust boundary, even with
signature verification in place — a compromised or misconfigured origin
still can't get an unsigned bundle accepted, but it can still serve stale
or wrong *signed* content if it has one, and the fetch itself needs
protecting:

- The bundle source URL must be `https://`. Nothing enforces this
  automatically today — a plain `http://` URL is accepted with no warning.
- Keep `/etc/apf/bundle-source-token` under the same access control as any
  other credential in this document — anyone holding it can trigger
  fetches against the source, even though they can't get unsigned content
  accepted.

General rules for this section:

- Bundle and trust-root files must be regular files owned by root, never
  symlinks — both daemons reject a trust or authority file whose final
  path component is a symlink or that has group/world write bits, so the
  ownership layout above is what makes that check meaningful rather than
  bypassable through a different path.
- The `apf` service account gets **read-only** access to `/etc/apf`. It
  cannot write back to its own config even if compromised.
- Bundle delivery and signing are a separate, out-of-band process (see
  `apf/docs/policy-publishing.md`) — nothing on this host mutates the
  bundle file. Anything that runs as `root` on this host is already inside
  the trust boundary; the ownership rules above stop the `apf` account and
  any other non-root service account from reading or writing APF/OpenShell
  config, not a compromised root.
- **OpenShell's own config gets the equivalent treatment**, under its own
  service account (`openshell`, not `apf`) with no group overlap — neither
  account should be able to read the other's secrets. If OpenShell and APF
  configuration end up readable by the same group, a compromise of either
  daemon reads both.
- **OpenShell's agent-driven policy-proposal surface must stay disabled**
  on any host where APF governs sandbox policy. If OpenShell can still
  accept agent- or developer-authored policy changes at runtime, the
  signed-bundle guarantee above is cosmetic — the effective policy is
  whatever OpenShell accepted most recently, not what was signed and
  distributed through APF. This is controlled by OpenShell's
  `agent_policy_proposals_enabled` setting, which defaults to `false`.
  Confirm it hasn't been turned on rather than assuming the default
  holds, and set it explicitly at global scope, which always overrides
  any per-sandbox value:
  ```
  openshell settings get --global
  openshell settings set --global --key agent_policy_proposals_enabled --value false
  ```
  There's no separate file-based lock for this — it's a runtime setting,
  the same kind of mutation surface it's meant to close — so re-check it
  as part of this checklist rather than treating a one-time `settings set`
  as permanent.

## 2. APF <-> OpenShell interface lockdown

Two distinct interfaces exist here and each needs a different lockdown.

**Control plane — `apf-policy-service` <-> `apf-policy-gateway`.** This
runs over a Unix domain socket, mode `0600`, and both daemons run as the
same `apf` account. That combination is a real access-control boundary,
not just defense-in-depth: a process running as any other account can't
even open the socket, let alone use it — the OS blocks the connection
before APF's own caller check ever runs. Nothing else on the host,
including root's interactive shell, can reach this socket without also
being the `apf` account.

**Data plane — `apf-policy-gateway` <-> OpenShell gateway/supervisor.**
This is gRPC over TLS (the sandbox-admission and per-request evaluation
hooks). Loopback-only is the right default for the co-located topology:
- Bind both addresses to `127.0.0.1` only (the shipped env file defaults
  to this — do not widen to `0.0.0.0` without a reviewed reason recorded
  in that file).
- The systemd units add a second enforcement layer restricting outbound
  network access to loopback, as a backstop against a misconfigured
  address — it doesn't replace the loopback bind, it backstops it.
- Add a host firewall rule dropping inbound to these ports from anything
  but loopback, independent of the systemd configuration — this is the
  layer that survives a unit file being edited or a future change that
  weakens the systemd-level restriction.

  OpenShell supports caller authentication for both hooks, configured
  independently per registration: gateway-minted, short-lived bearer tokens
  attached automatically, plus a pinned/private CA option instead of the
  platform trust store. Configure both, not just TLS — enable `gateway_jwt`
  and set an explicit `audience` and `tls_ca_cert_path` on each
  registration, in OpenShell's own gateway config. `allow_insecure_transport
  = true` is the explicit, logged opt-out for a registration that can't yet
  do this; don't set it here.

  **`apf-policy-gateway` now verifies that token and presents its own TLS
  identity on each surface — this is enforced, not optional, whenever that
  surface's address is set.** Each surface requires its own trust file
  (`--openshell-interceptor-auth-trust-file`/
  `--openshell-middleware-auth-trust-file` — a static TOML document
  containing the exact issuer, audience, signing `kid`, and OpenShell's
  Ed25519 public key, obtained from the matching OpenShell registration) and
  its own TLS certificate/key
  (`--openshell-{interceptor,middleware}-tls-cert-file`/`-tls-key-file` —
  the identity this process presents to OpenShell) — see `systemd/README.md`
  "Enabling the OpenShell seams" for the exact config. The gateway refuses
  to start a surface without all three of that surface's files present and
  valid; there's no unauthenticated fallback. Loopback bind and firewall
  stay in place as defense-in-depth on top of this, not a substitute for it
  — see the bullets above.

**Outbound calls from `apf-policy-gateway`** (to the OpenShell gateway for
reconciliation/refresh, and to the policy-service for its signing-key
endpoint) are egress from a policy-enforcing component, not from the
sandbox — but on a host with strict egress controls they still need to be
explicit, reviewed, loopback-scoped targets, same as any sandbox policy
entry. Don't treat "it's APF calling out, not the agent" as exempting it
from the same review.

**`apf-policy-service`'s HTTP surface is opt-in, and off by default.**
When enabled, the routes that return policy content or can trigger a
re-fetch require a bearer token — the service refuses to start without
one configured. Basic liveness/readiness checks stay open without a
token, since they don't return anything sensitive.

Deploying it: leave the HTTP surface disabled in the shipped config
unless something genuinely needs it. Health/readiness alone usually isn't
that reason — `apf-policy-gateway` already has a way to check
`apf-policy-service`'s liveness over the same control-plane connection
described above, without needing HTTP at all. The two real reasons to
turn HTTP on are: serving the signing-key document that `apf-policy-gateway`
needs for provenance verification, and answering a caller that isn't the
`apf` account and has no way to use the control-plane connection. If you
do enable it, follow `systemd/README.md`'s "Enabling the HTTP surface"
section for the exact steps (installing the bearer-token secret,
uncommenting the paired configuration). Two things that step doesn't
cover on its own:
- **Prefer not routing external monitoring at this port directly**, even
  for the routes that don't need a token. A narrow local reverse proxy in
  front that only forwards the liveness routes keeps the sensitive routes
  from ever being one misconfiguration away from being reachable
  off-host, even though they're already token-gated.
- **Firewall the port regardless.** Same as the TCP surfaces above — drop
  inbound from anything but loopback at the host level, independent of
  both the bind address and the token check, so a future config change or
  a bug in the auth logic doesn't silently expose it further.
  Defense-in-depth on top of the token, not a substitute for it.

## 3. Process-level lockdown

Goal: `apf-policy-service`/`apf-policy-gateway` can only be started,
stopped, or restarted through the deploy pipeline — never by an ad hoc
`systemctl restart` from an interactive session, and never by the process
replacing its own binary or unit file.

- **Binary and unit files are outside what the service can write.** The
  units are hardened so neither daemon (running as the non-root `apf`
  account, with the rest of the filesystem locked down) can modify its
  own binary or unit file even if compromised.
- **A polkit rule denies interactive restart/stop/start** of these two
  units to every local session. This closes the workstation-style path
  where a logged-in admin has passwordless sudo-via-polkit for
  `systemctl` — it does **not** and cannot restrict `root` itself, since
  the deploy pipeline's own restart path runs as root and never goes
  through polkit.
- **Restrict how `root` gets used for this, at the host level.** If admins
  reach root through general sudo, add a sudoers drop-in that only permits
  a specific wrapper script (e.g. `apf-service-ctl start|stop|restart
  apf-policy-service|apf-policy-gateway`) rather than raw `systemctl`/
  `kill` on these units. The wrapper is the place to enforce "supported
  flow" — e.g. requiring the pipeline's run ID as an argument and logging
  it, or refusing to restart `apf-policy-service` with a bundle whose
  signature it hasn't just verified. This is host/fleet config, not
  something this repo can ship a working default for — record whatever
  the actual wrapper/sudoers policy is here once it exists.
- **A restart-rate limit** in both units caps restart-loop abuse
  (accidental, or a compromised process crash-looping itself back into a
  fresh, differently-configured start).
- **Detect tampering, since prevention alone isn't provable.** Add auditd
  watches on the unit files, `/etc/apf`, and the two binaries so any
  modification to them is logged, and ship those watch rules as part of
  the same package/playbook that installs the units — not as a manual
  follow-up step.

## Open items

- The sudoers wrapper referenced in §3 is described, not shipped — this
  repo can define the unit-level restart lockdown but not the fleet's
  root-access policy.
- Confirm OpenShell's agent-driven policy-proposal setting is off wherever
  this unit set is deployed (§1) — that's an OpenShell-side setting, not
  something these units can enforce on their own.
