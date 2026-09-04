# votport — password-protected file receive portal built on VOT.
# VOTPORT PROPRIETARY LICENSE.
#
# Multi-stage build:
#   1. compile vot-wasm to WebAssembly for the browser uploader
#   2. compile the votport server
#   3. slim runtime image

# Pin the production-resolved toolchain and runtime inputs.
FROM rust:1.97@sha256:b1b3c9c0d921d7fa0a6d1f9ec7e4eab87f8c8ec97644c3d791450f131dec813f AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
# Must match the wasm-bindgen version pinned by vot-wasm.
RUN cargo install wasm-bindgen-cli --version 0.2.126 --locked
# Embeds the crate list in the binary so the image SBOM lists Rust crates,
# not only Debian packages.
RUN cargo install cargo-auditable --version 0.7.5 --locked

# Browser-side VOT: hashing, proofs, and package building in WebAssembly.
ARG VOT_GIT=https://github.com/halideworks/VOT
ARG VOT_REV=296174a794c58352b08c622d6ccdda5cb73122f2
RUN git clone --filter=blob:none "$VOT_GIT" /vot \
    && git -C /vot checkout "$VOT_REV"
RUN cd /vot \
    && cargo build --release -p vot-wasm --target wasm32-unknown-unknown --locked
RUN wasm-bindgen --target web --no-typescript --out-dir /wasm-vendor \
    /vot/target/wasm32-unknown-unknown/release/vot_wasm.wasm

# Server.
COPY LICENSE /src/LICENSE
COPY server/Cargo.toml server/Cargo.lock /src/server/
RUN mkdir -p /src/server/src \
    && printf 'fn main() {}\n' > /src/server/src/main.rs \
    && cd /src/server \
    && cargo build --release --locked
COPY server/src /src/server/src
RUN touch /src/server/src/main.rs /src/server/src/lib.rs \
    && cd /src/server \
    && cargo auditable build --release --locked

FROM debian:stable-slim@sha256:04634311a8d5fc442b6eb06d792293c4f3e2268652ca7634e00ce8ef5cc0a28a
# curl serves the healthcheck; CA roots serve HTTPS notification and S3 clients.
ARG VOTPORT_VERSION=dev
ARG VOTPORT_REVISION=unknown
LABEL org.opencontainers.image.version="$VOTPORT_VERSION" \
      org.opencontainers.image.revision="$VOTPORT_REVISION" \
      org.opencontainers.image.source="https://github.com/halideworks/votport" \
      org.opencontainers.image.licenses="LicenseRef-VOTPort-Proprietary"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && mkdir -p /app /data /received /outbound
COPY --from=build /src/server/target/release/votport /app/votport
COPY LICENSE /app/LICENSE
COPY web /app/web
COPY --from=build /wasm-vendor/ /app/web/assets/vendor/
RUN chmod -R a+rX /app/web

ENV VOTPORT_BIND=0.0.0.0:8080 \
    VOTPORT_DATA_DIR=/data \
    VOTPORT_RECEIVE_DIR=/received \
    VOTPORT_OUTBOUND_DIR=/outbound \
    VOTPORT_WEB_ROOT=/app/web

# Same uid the deployment's compose file uses; state, received, and outbound
# volumes must stay writable by it.
USER 1000:1000
EXPOSE 8080
VOLUME ["/data", "/received", "/outbound"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:8080/healthz -o /dev/null || exit 1
CMD ["/app/votport"]
