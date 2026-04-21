# Wraith C2

A lightweight, modular command-and-control framework written in Rust.

```
Operator Client ──gRPC──► C2 Server ◄──HTTP── (optional Redirector) ◄──HTTPS── Implant
```

---

## Components

| Crate | Role |
|---|---|
| `server` | C2 server — HTTP (implant + login) and gRPC (operator) |
| `client` | Operator GUI built with egui |
| `implant` | Agent that runs on target hosts |
| `redirector` | Optional HTTP relay between implant and server |
| `profiles` | Shared redirector profile types (TOML) |
| `shared` | Wire types + generated protobuf code |

---

## Setup

### Server (Docker — recommended)

**Prerequisites:** Docker, Docker Compose, Rust + `protoc` (client only)

```bash
# 1. Write credentials into secret files (input is hidden, files are chmod 600)
make docker-secrets

# 2. Start Postgres + server
make docker-up

# 3. Provision the admin account (first time only)
make docker-provision

# 4. Build and run the operator client locally
make client
```

Credentials are stored in `secrets/` as plain files mounted into containers at `/run/secrets/`.
They are **never passed as environment variables** and never appear in `docker inspect` output.
Postgres has no host port binding — it is unreachable from outside the Docker network.
The server binds to `127.0.0.1` only; put a reverse proxy (nginx, Caddy) in front for remote access.

### Server (manual — no Docker)

**Prerequisites:** Rust (stable), PostgreSQL 14+, `protoc`

```bash
createdb wraith
export DATABASE_URL=postgres://user:pass@localhost/wraith

make provision   # first time only
make server      # terminal 1
make client      # terminal 2
```

---

## Implant

Build for the current platform:
```bash
make implant
```

Cross-compile:
```bash
make implant-linux    # x86_64 musl static binary
make implant-windows  # x86_64 Windows (requires mingw-w64)
```

The implant binary accepts:
```
--server  <http://host:port>   C2 server (or redirector) base URL
--sleep   <seconds>            Beacon interval (default: 5)
--profile <name>               Profile name sent in check-in (default: "default")
```

---

## Redirector (optional)

The redirector is a thin HTTP proxy that sits in front of the server. Run it on a separate host to hide the true server IP from the target network.

```bash
make redirector PROFILE=profiles/examples/default-https.toml
```

Profile fields (TOML):
```toml
name       = "default-https"
user_agent = "Mozilla/5.0 ..."

[jitter]
min_ms = 500
max_ms = 2000

[transform]
uri_prefix = "/updates/"
```

When using a redirector, start the server with `--redirector-token <secret>` and set the same token in the redirector profile so only traffic from the redirector is accepted.

---

## Modules

Modules are Rust structs implementing the `Module` trait:

```rust
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, args: &[String]) -> serde_json::Value;
}
```

### Common (all platforms)

| Name | Args | Description |
|---|---|---|
| `shell` | `<command>` | Execute a shell command and return stdout/stderr |
| `file_get` | `<path>` | Read a file and return its contents (base64) |
| `file_put` | `<path> <base64>` | Write base64-encoded data to a file |
| `proc_list` | — | List running processes (pid, name, user) |
| `sysinfo` | — | Return hostname, OS, arch, uptime, users |

### Adding a module

1. Create `implant/src/modules/common/my_module.rs` (or in `linux/` or `windows/`)
2. Implement the `Module` trait
3. Register it in the corresponding `modules()` function in `mod.rs`

---

## Development

```bash
make build      # build all workspace crates
make check      # type-check only (fast)
make fmt        # format all code
make release    # release build
```

---

## Architecture notes

- **Authentication**: operators log in via `POST /api/login` and receive a UUID token stored in memory. The token is passed as `Authorization: Bearer <token>` in gRPC metadata.
- **Database**: PostgreSQL stores operators, implant sessions, and tasks. Sessions are upserted on each check-in; tasks are queued and returned to the implant on the next check-in.
- **Active detection**: a session is marked active if its `last_seen` timestamp is within the last 2 minutes.
- **Redirector token**: if the server is started with `--redirector-token`, implant HTTP routes require `X-Wraith-Token: <token>`. Omit the flag to allow direct connections.

---

## Security notes

- The server and gRPC port should not be exposed to the internet in production; use firewall rules or a VPN.
- Operator tokens are in-memory only and are lost on server restart (operators must log in again).
- See `FUTURE_FEATURES.md` for planned hardening (mTLS, RBAC, audit log).

---

## Project layout

```
Wraith/
├── Cargo.toml            workspace manifest
├── Makefile              task runner recipes
├── docker-compose.yml
├── docker/
│   └── Dockerfile
├── .env.example
├── proto/
│   └── orchestrator.proto
├── shared/               wire types + protobuf generated code
├── server/               C2 server (axum HTTP + tonic gRPC + sqlx PG)
├── client/               operator GUI (eframe/egui)
├── implant/              agent (beacon loop + module registry)
│   └── src/modules/
│       ├── common/       shell, file_get, file_put, proc_list, sysinfo
│       ├── linux/        (stub — persist, privesc planned)
│       └── windows/      (stub — screenshot, token, inject, persist planned)
├── redirector/           optional HTTP relay
├── profiles/             shared redirector profile types
├── FUTURE_FEATURES.md
└── README.md
```
