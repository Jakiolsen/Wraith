# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential protobuf-compiler pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release -p server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd --no-create-home --shell /bin/false wraith

COPY --from=builder /build/target/release/server /usr/local/bin/wraith-server
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    chown wraith:wraith /usr/local/bin/wraith-server /entrypoint.sh

USER wraith

EXPOSE 8080 50051

ENTRYPOINT ["/entrypoint.sh"]
CMD ["wraith-server"]
