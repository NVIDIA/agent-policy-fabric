# SPDX-License-Identifier: Apache-2.0
# APF Policy Gateway image.
#
# Build from repo root:
#   docker build -f deploy/apf-policy-gateway/Dockerfile -t apf-policy-gateway:dev .

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

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=secret,id=artifactory_token \
    CARGO_REGISTRIES_ARTIFACTORY_TOKEN=$(cat /run/secrets/artifactory_token 2>/dev/null || true) \
    cargo build --release -p apf-policy-gateway && \
    cp target/release/apf-policy-gateway /apf-policy-gateway

# ── runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /apf-policy-gateway /usr/local/bin/apf-policy-gateway

RUN mkdir -p /run/apf /run/apf-gateway /var/lib/apf /data/keys /etc/apf

ENV APF_GATEWAY_SOCKET=/run/apf-gateway/policy-gateway.sock \
    APF_POLICY_SERVICE_SOCKET=/run/apf/policy-service.sock \
    APF_TRUST_ROOT_DIR=/data/keys \
    APF_COUNTER_STORE=/var/lib/apf/gateway-counter \
    APF_DOCUMENT_KEY_ID=apf-dev

ENTRYPOINT ["apf-policy-gateway"]
