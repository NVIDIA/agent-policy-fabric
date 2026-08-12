# SPDX-License-Identifier: Apache-2.0
# APF Policy Service image.
#
# Build from repo root (Artifactory token required for yaml-sigil deps):
#   docker build \
#     --secret id=artifactory_token,env=CARGO_REGISTRIES_ARTIFACTORY_TOKEN \
#     -f deploy/apf-policy-service/Dockerfile -t apf-policy-service:demo --target demo .
#
# Targets:
#   runtime  — minimal production image
#   demo     — adds apf-compile for bundle signing

# ── build ─────────────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS build

ARG BUF_VERSION=1.50.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler libprotobuf-dev curl \
    && ARCH="$(dpkg --print-architecture | sed 's/amd64/x86_64/;s/arm64/aarch64/')" \
    && curl -sSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-${ARCH}" \
        -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# apf-proto/build.rs uses contracts/proto-ir/ if present (vendored via `mise run vendor-proto`),
# avoiding the need for buf or BSR credentials inside the container.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=secret,id=artifactory_token \
    CARGO_REGISTRIES_ARTIFACTORY_TOKEN=$(cat /run/secrets/artifactory_token 2>/dev/null || true) \
    cargo build --release -p apf-policy-service -p apf-compile && \
    cp target/release/apf-policy-service /apf-policy-service && \
    cp target/release/apf-compile /apf-compile

# ── runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /apf-policy-service /usr/local/bin/apf-policy-service

RUN mkdir -p /run/apf /var/lib/apf /data/bundles /data/keys /etc/apf

EXPOSE 19200

ENV APF_SOCKET=/run/apf/policy-service.sock \
    APF_HTTP_ADDR=0.0.0.0:19200 \
    APF_TRUST_ROOT_DIR=/data/keys \
    APF_COUNTER_STORE=/var/lib/apf/counter \
    APF_DOCUMENT_KEY_ID=apf-dev \
    APF_POLICY_SOURCE=local

ENTRYPOINT ["apf-policy-service", "serve"]

# ── demo ──────────────────────────────────────────────────────────────────────
FROM runtime AS demo

COPY --from=build /apf-compile /usr/local/bin/apf-compile
