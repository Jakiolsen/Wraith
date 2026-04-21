# Wraith C2 — task runner  (requires: https://github.com/casey/just)
# Usage: just <recipe>

default:
    @just --list

# ── Development ───────────────────────────────────────────────────────────────

# Build all workspace crates
build:
    cargo build

# Release build
release:
    cargo build --release

# Type-check without producing binaries
check:
    cargo check --all

# Format all code
fmt:
    cargo fmt --all

# ── Server ────────────────────────────────────────────────────────────────────

# Run the C2 server (HTTP + gRPC)
server:
    cargo run -p server -- \
        --http-addr 127.0.0.1:8080 \
        --grpc-addr 127.0.0.1:50051

# Create or reset the admin operator account
provision:
    cargo run -p server -- provision-admin

# ── Operator client ───────────────────────────────────────────────────────────

# Run the operator GUI
client:
    cargo run -p client -- \
        --server http://127.0.0.1:8080 \
        --grpc   http://127.0.0.1:50051

# ── Implant ───────────────────────────────────────────────────────────────────

# Build implant for the current host platform
implant:
    cargo build --release -p implant

# Cross-compile for 64-bit Linux (static musl binary)
implant-linux:
    cargo build --release -p implant --target x86_64-unknown-linux-musl

# Cross-compile for 64-bit Windows (requires: rustup target add x86_64-pc-windows-gnu && apt install mingw-w64)
implant-windows:
    cargo build --release -p implant --target x86_64-pc-windows-gnu

# ── Redirector ────────────────────────────────────────────────────────────────

# Run the redirector with a profile (optional — implants can also connect directly)
redirector profile="profiles/examples/default-https.toml":
    cargo run -p redirector -- \
        --profile  {{profile}} \
        --upstream http://127.0.0.1:8080 \
        --listen   0.0.0.0:8443

# ── Docker ────────────────────────────────────────────────────────────────────

# Start postgres + server (detached)
docker-up:
    docker compose up -d

# Stop and remove containers (data volume is preserved)
docker-down:
    docker compose down

# Stop and remove containers AND wipe the database volume
docker-clean:
    docker compose down -v

# Tail server logs
docker-logs:
    docker compose logs -f server

# Create (or reset) the admin account inside the running server container
docker-provision username="admin":
    docker compose exec server wraith-server provision-admin --username {{username}}

# Rebuild the server image after code changes
docker-build:
    docker compose build server
