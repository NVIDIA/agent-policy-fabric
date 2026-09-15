# SPDX-License-Identifier: Apache-2.0
# APF Policy Service image.
#
# Build from repo root:
#   docker build -f deploy/docker/apf-policy-service/Dockerfile -t apf-policy-service:demo --target demo .
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

# apf-proto/build.rs vendors APF's own IR protos from contracts/proto/; buf is
# only needed here to export OpenShell's protos from GitHub at build time.
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

# APF_HTTP_ADDR is opt-in, not defaulted here: apf-policy-service refuses to
# start with it set unless APF_HTTP_BEARER_TOKEN_FILE is also provided (see
# apf-policy-service/src/surfaces/http.rs). Set both at `docker run`/compose
# time — deploy/docker-compose.yml does this for the dev stack.
ENV APF_SOCKET=/run/apf/policy-service.sock \
    APF_TRUST_ROOT_DIR=/data/keys \
    APF_COUNTER_STORE=/var/lib/apf/counter \
    APF_DOCUMENT_KEY_ID=apf-dev \
    APF_POLICY_SOURCE=local

ENTRYPOINT ["apf-policy-service", "serve"]

# ── demo ──────────────────────────────────────────────────────────────────────
FROM runtime AS demo

COPY --from=build /apf-compile /usr/local/bin/apf-compile
