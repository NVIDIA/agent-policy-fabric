# SPDX-License-Identifier: Apache-2.0
# APF Policy Gateway image.
#
# Build from repo root:
#   docker build -f deploy/apf-policy-gateway/Dockerfile -t apf-policy-gateway:dev .

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.36

# ── build ─────────────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS build

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p apf-policy-gateway && \
    cp target/release/apf-policy-gateway /apf-policy-gateway

# ── grpc-health-probe ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS probe-fetch
ARG GRPC_HEALTH_PROBE_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    ARCH="$(dpkg --print-architecture)" && \
    curl -fsSL "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${ARCH}" \
        -o /grpc_health_probe && \
    chmod +x /grpc_health_probe

# ── runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /apf-policy-gateway /usr/local/bin/apf-policy-gateway
COPY --from=probe-fetch /grpc_health_probe /usr/local/bin/grpc_health_probe

RUN mkdir -p /run/apf /run/apf-gateway /var/lib/apf /data/keys /etc/apf

ENV APF_GATEWAY_SOCKET=/run/apf-gateway/policy-gateway.sock \
    APF_POLICY_SERVICE_SOCKET=/run/apf/policy-service.sock \
    APF_TRUST_ROOT_DIR=/data/keys \
    APF_COUNTER_STORE=/var/lib/apf/gateway-counter \
    APF_DOCUMENT_KEY_ID=apf-dev

ENTRYPOINT ["apf-policy-gateway"]
