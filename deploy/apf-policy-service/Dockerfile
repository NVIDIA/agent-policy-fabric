# SPDX-License-Identifier: Apache-2.0
# APF Policy Service image.
#
# Build from repo root:
#   docker build -f deploy/apf-policy-service/Dockerfile -t apf-policy-service:dev .
#
# Targets:
#   runtime  — minimal production image (no build tools)
#   demo     — same binary, also includes apf-compile for bundle signing at demo startup

# ── build ─────────────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS build

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
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
