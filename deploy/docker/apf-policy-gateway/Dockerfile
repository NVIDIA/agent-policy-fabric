# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# APF Policy Gateway image.
#
# Build from repo root:
#   docker build -f deploy/docker/apf-policy-gateway/Dockerfile -t apf-policy-gateway:dev .

# ── build ─────────────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p apf-policy-gateway && \
    cp target/release/apf-policy-gateway /apf-policy-gateway

# ── runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /apf-policy-gateway /usr/local/bin/apf-policy-gateway
COPY --from=build /src/LICENSE /src/THIRD_PARTY_LICENSES.txt /usr/share/licenses/apf/

RUN mkdir -p /run/apf /run/apf-gateway /var/lib/apf /data/keys /etc/apf

ENV APF_GATEWAY_SOCKET=/run/apf-gateway/policy-gateway.sock \
    APF_POLICY_SERVICE_SOCKET=/run/apf/policy-service.sock \
    APF_TRUST_ROOT_DIR=/data/keys \
    APF_COUNTER_STORE=/var/lib/apf/gateway-counter \
    APF_DOCUMENT_KEY_ID=apf-dev

ENTRYPOINT ["apf-policy-gateway"]
