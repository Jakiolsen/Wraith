# Wraith C2 — task runner
.PHONY: help build release check fmt test \
        client \
        implant implant-linux implant-windows \
        docker-up docker-down docker-clean \
        docker-logs docker-redirector-logs \
        docker-provision docker-build docker-redirector-build \
        docker-secrets

PROFILE  ?= profiles/examples/default-https.toml
USERNAME ?= admin

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-26s %s\n", $$1, $$2}'

# ── Development ───────────────────────────────────────────────────────────────

build: ## Build all workspace crates
	cargo build

release: ## Release build (all crates)
	cargo build --release

check: ## Type-check without producing binaries
	cargo check --all

fmt: ## Format all code
	cargo fmt --all

test: ## Run all tests
	cargo test --all

# ── Operator client ───────────────────────────────────────────────────────────

client: ## Build and run the operator GUI
	cargo build -p client
	./target/debug/client \
		--server http://127.0.0.1:8080 \
		--grpc   http://127.0.0.1:50051

# ── Implant ───────────────────────────────────────────────────────────────────

implant: ## Build implant for the current host platform
	cargo build --release -p implant

implant-linux: ## Cross-compile implant for x86_64 Linux (static musl binary)
	cargo build --release -p implant --target x86_64-unknown-linux-musl

implant-windows: ## Cross-compile implant for x86_64 Windows (requires mingw-w64)
	cargo build --release -p implant --target x86_64-pc-windows-gnu

# ── Docker ────────────────────────────────────────────────────────────────────

docker-secrets: ## Write secret files interactively (input is hidden)
	@mkdir -p secrets
	@printf 'Postgres password (input hidden): '; stty -echo; read PG; stty echo; echo; \
	printf '%s' "$$PG" > secrets/postgres_password; chmod 600 secrets/postgres_password; \
	echo "secrets/postgres_password written."; \
	printf 'Redirector token (leave blank to skip): '; stty -echo; read RT; stty echo; echo; \
	if [ -n "$$RT" ]; then \
		printf '%s' "$$RT" > secrets/redirector_token; \
		chmod 600 secrets/redirector_token; \
		echo "secrets/redirector_token written."; \
	else \
		printf '' > secrets/redirector_token; \
		echo "secrets/redirector_token left empty (direct connections allowed)."; \
	fi

docker-up: ## Start all services (detached)
	docker compose up -d

docker-down: ## Stop containers (data volume preserved)
	docker compose down

docker-clean: ## Stop containers and delete the database volume
	docker compose down -v

docker-logs: ## Tail server logs
	docker compose logs -f server

docker-redirector-logs: ## Tail redirector logs
	docker compose logs -f redirector

docker-provision: ## Create or reset the admin account inside Docker
	docker compose exec server /entrypoint.sh wraith-server provision-admin --username $(USERNAME)

docker-build: ## Rebuild the server image after code changes
	docker compose build server

docker-redirector-build: ## Rebuild the redirector image after code changes
	docker compose build redirector
