# votport — password-protected file receive portal built on VOT.
# AGPL-3.0-only.
#
# Multi-stage build:
#   1. compile vot-wasm to WebAssembly for the browser uploader
#   2. compile the votport server
#   3. slim runtime image

ARG VOT_GIT=https://github.com/halideworks/VOT
ARG VOT_REV=976065296e2d2d2ec2a31c480dcaeddb93dc8aa3

FROM rust:1 AS build
ARG VOT_GIT
ARG VOT_REV

RUN rustup target add wasm32-unknown-unknown
# Must match the wasm-bindgen version pinned by vot-wasm.
RUN cargo install wasm-bindgen-cli --version 0.2.126 --locked

# Browser-side VOT: hashing, proofs, and package building in WebAssembly.
RUN git clone --filter=blob:none "$VOT_GIT" /vot \
    && git -C /vot checkout "$VOT_REV"
# Browser hashing is the slowest step a sender sees, and the default wasm build
# gets scalar BLAKE3 (~430 MiB/s measured). blake3's wasm32_simd implementation
# does not participate in runtime feature detection, so it needs BOTH the cargo
# feature and +simd128 at compile time. Enabling the feature adds no
# dependencies, so --locked still holds.
RUN cd /vot \
    && sed -i 's|^blake3 = "1.8.5"$|blake3 = { version = "1.8.5", features = ["wasm32_simd"] }|' Cargo.toml \
    && grep -q 'wasm32_simd' Cargo.toml \
    && RUSTFLAGS="-C target-feature=+simd128" \
       cargo build --release -p vot-wasm --target wasm32-unknown-unknown --locked
RUN wasm-bindgen --target web --no-typescript --out-dir /wasm-vendor \
    /vot/target/wasm32-unknown-unknown/release/vot_wasm.wasm

# Server.
COPY server /src/server
RUN cd /src/server && cargo build --release

FROM debian:stable-slim
RUN mkdir -p /app /data /received
COPY --from=build /src/server/target/release/votport /app/votport
COPY web /app/web
COPY --from=build /wasm-vendor/ /app/web/assets/vendor/

ENV VOTPORT_BIND=0.0.0.0:8080 \
    VOTPORT_DATA_DIR=/data \
    VOTPORT_RECEIVE_DIR=/received \
    VOTPORT_WEB_ROOT=/app/web

EXPOSE 8080
VOLUME ["/data", "/received"]
CMD ["/app/votport"]
