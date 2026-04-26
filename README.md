# Wraith C2

A modular, OPSEC-focused command-and-control framework written in Rust.

```
Operator Client ──gRPC──► C2 Server ◄──HTTP── Redirector ◄──HTTPS── Implant
                               │
                           PostgreSQL
```

The server and redirector run inside Docker only. The operator client runs locally. The implant is a standalone binary deployed to target hosts.

---

## Components

| Crate | Role |
|---|---|
| `server` | C2 server — HTTP (implant check-ins) and gRPC (operator API) |
| `client` | Operator GUI built with egui |
| `implant` | Agent that beacons from target hosts |
| `redirector` | HTTP relay that hides the true server IP from targets |
| `profiles` | Shared C2 profile types (TOML) |
| `shared` | Wire types + generated protobuf code |

---

## Quick start

**Prerequisites:** Docker, Docker Compose, Rust (stable)

```bash
# 1. Write secret files (postgres password, CA passphrase, redirector token)
make docker-secrets

# 2. Start Postgres + server + redirector
make docker-up

# 3. Issue an operator mTLS certificate (writes to ./certs/)
make docker-provision        # USERNAME=admin by default

# 4. Build and run the operator client with the provisioned cert
make client                  # USERNAME=admin by default
```

The server exposes two ports on `127.0.0.1` only:
- `:8080` — implant check-ins (plain HTTP, token-gated by redirector token)
- `:50051` — gRPC operator API (mTLS — client certificate required)

The redirector exposes `:8443` on all interfaces — this is the address implants contact in production.

Credentials live in `secrets/` as files mounted at `/run/secrets/` inside containers. They are never passed as environment variables and never appear in `docker inspect` output. Postgres has no host-port binding and is unreachable outside the Docker network.

---

## Implant

### Building

```bash
make implant                # current host platform
make implant-linux          # x86_64 musl static binary (no libc dependency)
make implant-windows        # x86_64 Windows (requires mingw-w64)
```

### Configuration

The implant has no CLI flags. All settings are baked in at compile time via environment variables:

| Variable | Default | Description |
|---|---|---|
| `WRAITH_C2_URL` | `http://127.0.0.1:8080` | C2 base URL (redirector or server) |
| `WRAITH_CHECKIN_URI` | `/implant/checkin` | Check-in endpoint path |
| `WRAITH_RESULT_URI` | `/implant/result` | Task result endpoint path |
| `WRAITH_PROFILE` | `default-https` | Profile name sent in check-in |

Example cross-compile targeting a redirector:
```bash
WRAITH_C2_URL=https://redirector.example.com:8443 \
WRAITH_CHECKIN_URI=/api/v1/update \
WRAITH_RESULT_URI=/api/v1/result \
  make implant-linux
```

A `wraith.json` file in the implant's working directory overrides compile-time defaults at runtime. This is intended for lab use only — in production, bake everything in at compile time and deploy with no config file on disk.

---

## Redirector

The redirector is managed by Docker Compose and starts automatically with `make docker-up`.

It reads profile files from `profiles/examples/` and forwards matching URIs to the server over the internal Docker network. Unmatched requests get a 404 or are proxied to a configured decoy URL.

```bash
make docker-redirector-logs   # tail redirector output
make docker-redirector-build  # rebuild after code changes
```

### Profiles (TOML)

Profiles control URI patterns, headers, jitter, and routing:

```toml
[profile]
name       = "default-https"
sleep_ms   = 5000
jitter_pct = 20

[transport]
protocol = "https"
host     = "redirector.example.com"
port     = 443

[http]
checkin_uri = "/api/v1/update"
result_uri  = "/api/v1/result"
user_agent  = "Mozilla/5.0 ..."

[server]
# Must match the redirector_token secret set via `make docker-secrets`.
redirector_token     = ""
internal_checkin_uri = "/implant/checkin"
internal_result_uri  = "/implant/result"
decoy_url            = "https://example.com"
```

Two example profiles are in `profiles/examples/`: a clean API-style profile and a jQuery CDN mimic.

---

## Modules

Modules implement a single trait:

```rust
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, args: &[String]) -> serde_json::Value;
}
```

### Built-in modules (all platforms)

| Module | Args | Description |
|---|---|---|
| `shell` | `<command>` | Execute a shell command and return stdout/stderr |
| `file_get` | `<path>` | Read a file and return base64-encoded contents |
| `file_put` | `<path> <base64>` | Write base64-encoded data to a file |
| `proc_list` | — | List running processes (pid, name, user) |
| `sysinfo` | — | Return hostname, OS, arch, uptime, users |

### Adding a module

1. Create `implant/src/modules/common/my_module.rs` (or `linux/` or `windows/`)
2. Implement the `Module` trait
3. Register it in the corresponding `modules()` function in `mod.rs`

---

## Development

```bash
make build      # build all workspace crates
make check      # type-check only (fast)
make fmt        # format all code
make test       # run all tests
make release    # release build
```

---

## Architecture

- **Auth**: mutual TLS on all gRPC connections. The server generates its own CA on first start (key encrypted at rest with AES-256-GCM, Argon2id KDF with locked params). Operators are issued leaf certs via `provision-operator`; the cert's CN is the operator username and OU is the role. No passwords, no bearer tokens.
- **CA key in RAM**: the CA private key is dropped from process memory immediately after the TLS listener is configured. It is not resident while the server is handling connections.
- **CRL**: revoked cert serials are stored in Postgres and loaded into memory every 60 seconds. Revoking an operator takes effect within one refresh cycle. Re-provisioning a cert automatically revokes the previous one.
- **Database**: PostgreSQL stores CA state, operator certs, CRL, implant sessions, and tasks. Sessions are upserted on every check-in; tasks are queued and returned to the implant on the next check-in.
- **Session integrity**: the server only accepts a client-supplied session ID if it was previously issued by this server. Unknown IDs trigger re-registration. Task results are cross-referenced by `(task_id, session_id)` so one implant cannot overwrite another's results.
- **Body limit**: implant HTTP endpoints reject requests over 1 MB (returns 413).
- **Active detection**: a session is marked active if `last_seen` is within the last 2 minutes. All timestamps are UTC.
- **Redirector token**: if the `redirector_token` secret is non-empty, implant HTTP routes require `x-wraith-redirector-token: <token>` (constant-time comparison). Leave it empty to allow direct connections.
- **Beacon jitter**: sleep duration is randomised ±`jitter_pct`% each cycle. Step 6 of the plan replaces this with a CSPRNG (`getrandom`).

---

## Security notes

- `CA_PASSPHRASE` is required at startup. The server refuses to start if it is absent or empty unless `--dev-no-passphrase` is explicitly passed (development only).
- Operator private key files are written with mode 0600 — not readable by other local users regardless of umask.
- Operator private keys are never stored server-side — generated during provisioning, returned once, gone.
- The gRPC port (50051) defaults to `127.0.0.1` and is only accessible from the host machine. In Docker, port isolation is enforced by the `127.0.0.1:50051:50051` mapping in `docker-compose.yml`.
- Postgres is unreachable outside the Docker network; credentials are never in env vars or logs.
- To revoke an operator: `docker compose run --rm server wraith-server revoke-operator --username <n>`. Takes effect on the next connection attempt (within 60 seconds).
- See `PLAN.md` for the full implementation roadmap including RBAC, audit logging, and evasion.

---

## Project layout

```
Wraith/
├── Cargo.toml               workspace manifest
├── Makefile                 task runner
├── PLAN.md                  implementation roadmap
├── docker-compose.yml
├── docker/
│   ├── Dockerfile           server image (cargo-chef 4-stage build)
│   ├── Dockerfile.redirector
│   ├── entrypoint.sh        reads postgres_password + ca_passphrase secrets
│   └── entrypoint.redirector.sh  reads redirector_token secret
├── secrets/                 credential files (git-ignored)
│   ├── postgres_password
│   ├── ca_passphrase        encrypts the CA private key at rest
│   └── redirector_token
├── certs/                   operator cert/key files (git-ignored, written by make docker-provision)
├── shared/                  wire types + protobuf generated code
├── server/                  C2 server (axum HTTP + tonic gRPC mTLS + sqlx PG)
├── client/                  operator GUI (eframe/egui, mTLS connect)
├── implant/                 agent (beacon loop + module registry)
│   └── src/modules/
│       ├── common/          shell, file_get, file_put, proc_list, sysinfo
│       ├── linux/           (stub — Step 7: persist, privesc, screenshot, keylog)
│       └── windows/         (stub — Step 12: inject, token, persist, harvest)
├── redirector/              profile-aware HTTP relay
└── profiles/
    ├── src/                 C2Profile types
    └── examples/            default-https.toml, jquery-malleable.toml
```
