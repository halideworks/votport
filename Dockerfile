# votport — password-protected file receive portal built on VOT.
# AGPL-3.0-only.
#
# Multi-stage build:
#   1. compile vot-wasm to WebAssembly for the browser uploader
#   2. compile the votport server
#   3. slim runtime image

# Pinned to the version CI tests against; rust-version in Cargo.toml only
# guards older toolchains, so a floating tag would let production drift.
FROM rust:1.97 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
# Must match the wasm-bindgen version pinned by vot-wasm.
RUN cargo install wasm-bindgen-cli --version 0.2.126 --locked

# Browser-side VOT: hashing, proofs, and package building in WebAssembly.
ARG VOT_GIT=https://github.com/halideworks/VOT
ARG VOT_REV=b14cc41debc2547c5ef999fee26bb055995284d9
RUN git clone --filter=blob:none "$VOT_GIT" /vot \
    && git -C /vot checkout "$VOT_REV"
RUN cd /vot \
    && cargo build --release -p vot-wasm --target wasm32-unknown-unknown --locked
RUN wasm-bindgen --target web --no-typescript --out-dir /wasm-vendor \
    /vot/target/wasm32-unknown-unknown/release/vot_wasm.wasm

# Server.
COPY server /src/server
RUN cd /src/server && cargo build --release --locked

FROM debian:stable-slim
# curl exists only for the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app /data /received /outbound
COPY --from=build /src/server/target/release/votport /app/votport
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
    CMD curl -sf http://127.0.0.1:8080/ -o /dev/null || exit 1
CMD ["/app/votport"]
