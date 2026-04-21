# Wraith C2 — task runner
# Usage: make <target>

.PHONY: help build release check fmt \
        server provision client \
        implant implant-linux implant-windows \
        redirector \
        docker-up docker-down docker-clean docker-logs docker-provision docker-build

PROFILE  ?= profiles/examples/default-https.toml
USERNAME ?= admin

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# ── Development ───────────────────────────────────────────────────────────────

build: ## Build all workspace crates
	cargo build

release: ## Release build
	cargo build --release

check: ## Type-check without producing binaries
	cargo check --all

fmt: ## Format all code
	cargo fmt --all

# ── Server ────────────────────────────────────────────────────────────────────

server: ## Run the C2 server (HTTP + gRPC)
	cargo run -p server -- \
		--http-addr 127.0.0.1:8080 \
		--grpc-addr 127.0.0.1:50051

provision: ## Create or reset the admin operator account
	cargo run -p server -- provision-admin

# ── Operator client ───────────────────────────────────────────────────────────

client: ## Run the operator GUI
	cargo run -p client -- \
		--server http://127.0.0.1:8080 \
		--grpc   http://127.0.0.1:50051

# ── Implant ───────────────────────────────────────────────────────────────────

implant: ## Build implant for the current host platform
	cargo build --release -p implant

implant-linux: ## Cross-compile for 64-bit Linux (static musl binary)
	cargo build --release -p implant --target x86_64-unknown-linux-musl

implant-windows: ## Cross-compile for 64-bit Windows (requires mingw-w64)
	cargo build --release -p implant --target x86_64-pc-windows-gnu

# ── Redirector ────────────────────────────────────────────────────────────────

redirector: ## Run the redirector (override profile with PROFILE=path/to/profile.toml)
	cargo run -p redirector -- \
		--profile  $(PROFILE) \
		--upstream http://127.0.0.1:8080 \
		--listen   0.0.0.0:8443

# ── Docker (server + database) ────────────────────────────────────────────────

docker-secrets: ## Interactively write secret files (secrets/postgres_password etc.)
	@printf 'Postgres password (input hidden): '; stty -echo; read PG; stty echo; echo; \
	printf '%s' "$$PG" > secrets/postgres_password; chmod 600 secrets/postgres_password; \
	echo "secrets/postgres_password written."; \
	printf 'Redirector token (leave blank to skip): '; stty -echo; read RT; stty echo; echo; \
	if [ -n "$$RT" ]; then printf '%s' "$$RT" > secrets/redirector_token; chmod 600 secrets/redirector_token; echo "secrets/redirector_token written."; fi

docker-up: ## Start Postgres + server in Docker (detached)
	docker compose up -d

docker-down: ## Stop containers (data volume preserved)
	docker compose down

docker-clean: ## Stop containers and delete the database volume
	docker compose down -v

docker-logs: ## Tail server logs
	docker compose logs -f server

docker-provision: ## Create or reset admin account (USERNAME=name to override)
	docker compose exec server /entrypoint.sh wraith-server provision-admin --username $(USERNAME)

docker-build: ## Rebuild the server image after code changes
	docker compose build server

