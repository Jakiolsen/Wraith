# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.87-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release -p server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/server /usr/local/bin/wraith-server

EXPOSE 8080 50051

ENTRYPOINT ["wraith-server"]
