# ── Stage 1: dependency cache (cargo-chef) ────────────────────────────────────
FROM rust:slim AS planner
WORKDIR /build
RUN cargo install cargo-chef --locked
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: compile dependencies ─────────────────────────────────────────────
FROM rust:slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential protobuf-compiler pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release -p server --recipe-path recipe.json

# ── Stage 3: build the server binary ──────────────────────────────────────────
COPY . .
RUN cargo build --release -p server

# ── Stage 4: minimal runtime image ────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --no-create-home --shell /bin/false wraith

COPY --from=builder /build/target/release/wraith-server /usr/local/bin/wraith-server
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    chown wraith:wraith /usr/local/bin/wraith-server /entrypoint.sh

USER wraith

EXPOSE 8080 50051

ENTRYPOINT ["/entrypoint.sh"]
CMD ["wraith-server"]
