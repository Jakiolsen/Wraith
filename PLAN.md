# Wraith C2 — Implementation Plan

**Core philosophy:** Assume every piece of infrastructure will eventually be identified.
Design every layer so that when it is burned, the damage is contained, the operator is
not exposed, and operations can resume from a clean slate within minutes.
Security is not a phase — it is the foundation every other decision is built on.

---

## OPSEC Principles

Every decision follows these rules. When in doubt, the more conservative option wins.

1. **Assume burn** — every IP, domain, and certificate will eventually be identified. Design so that when it happens, the operator is not exposed and operations resume within minutes.
2. **Compartmentalise** — one engagement cannot affect another. One burned redirector cannot reveal the server. One compromised operator cert cannot compromise others.
3. **Minimal footprint** — never write to disk if memory works. Never spawn a process if in-process works. Never leave an artefact that isn't tracked for cleanup.
4. **Fail closed** — when anything is uncertain (sandbox, honeypot, unexpected response), the implant does nothing and sleeps rather than proceeding.
5. **No plaintext secrets anywhere** — not in env vars, not in logs, not in database columns, not in HTTP responses.
6. **Operator is not the server** — the operator's machine never has a direct network path to the C2 server.

---

## Current State

| Crate | Status |
|---|---|
| `server` | ✅ HTTP + gRPC + PostgreSQL + Argon2id auth + Docker |
| `implant` | ✅ Beacon loop, jitter, 5 common modules |
| `client` | ✅ Login screen, sessions table, task console, dark theme |
| `redirector` | ✅ Profile-aware relay, allowlist routing, decoy proxy, Docker |
| `profiles` | ✅ Full `C2Profile` types, 2 example profiles |
| `shared` | ✅ Wire types + protobuf codegen (vendored protoc) |

Everything below builds on top of this in strict dependency order.
Do not advance to the next step until the current one compiles, passes tests, and behaves correctly.

---

## Step-by-Step Implementation

### ✅ Step 1 — Working Baseline

**1.1 Proto + shared wire types** ✅
- `proto/orchestrator.proto`: `ListSessions`, `TaskSession`, `ListSessionTasks`
- `shared/build.rs` codegen via `tonic-prost-build` + vendored `protoc` (no system install needed)
- Wire types (`ImplantCheckin`, `ImplantTask`, `ImplantTaskResult`, auth types) in `shared/src/lib.rs`

**1.2 PostgreSQL + sqlx** ✅
- Tables created at startup: `operators`, `implant_sessions`, `implant_tasks`
- `DATABASE_URL` from Docker secret via `entrypoint.sh`; server refuses to start if connection fails
- `provision-admin` subcommand creates/resets admin account, prints password once

**1.3 Docker Compose** ✅
- `docker-compose.yml`: `postgres` (no host port, healthcheck) + `server` (localhost-only ports) + `redirector`
- `docker/Dockerfile`: 4-stage build — planner → builder → runtime (cargo-chef layer caching)
- `docker/Dockerfile.redirector`: same pattern for the redirector binary
- `docker/entrypoint.sh`: reads `postgres_password` secret, constructs `DATABASE_URL`, execs server
- `docker/entrypoint.redirector.sh`: reads `redirector_token` secret, exports as `WRAITH_REDIRECTOR_TOKEN`
- All credentials via Docker secrets at `/run/secrets/`; never env vars
- `secrets/.gitignore` prevents committing credentials
- `/etc/localtime:/etc/localtime:ro` volume mount on server container for host-timezone-aware timestamps

**1.4 Makefile** ✅
- Targets: `build`, `check`, `fmt`, `test`, `client`, `implant`, `implant-linux`, `implant-windows`, `docker-up/down/clean/logs/redirector-logs/provision/build/redirector-build`, `docker-secrets`
- Server and redirector run only inside Docker; no bare-metal run targets

**1.5 Implant beacon loop** ✅
- `implant/src/beacon.rs`: checkin → execute tasks → post results → jittered sleep
- `implant/src/config.rs`: compile-time defaults overridable via `WRAITH_C2_URL`, `WRAITH_CHECKIN_URI`, `WRAITH_RESULT_URI`, `WRAITH_PROFILE`; optional runtime `wraith.json` override
- Hostname resolved via `sysinfo::System::host_name()` (OS-level `gethostname`); env vars are unreliable in non-interactive shells
- Beacon errors (checkin failure, result post failure) are silently swallowed; no stderr output on target host

**1.6 Common modules** ✅
- `shell`, `file_get`, `file_put`, `proc_list`, `sysinfo`
- Module registry with platform-conditional `linux/` and `windows/` extension points
- `proc_list` returns `pid`, `ppid`, `name`, `user`, `mem_kb`, `path` per process; client renders as ASCII process tree (recursive parent→child traversal using ppid)
- `sysinfo` pretty-printed in client: hostname, OS, kernel, arch, CPU count, memory bar `[████░░░░]`, uptime as `Xd Xh Xm`
- `x-wraith-redirector-token` used consistently on all paths (server check-in handler and redirector upstream request)

**1.7 gRPC server** ✅
- `ListSessions`, `TaskSession`, `ListSessionTasks` on port 50051
- Bearer token auth (token issued at login, validated on every call)

**1.8 Operator client** ✅
- Login screen → sessions table (auto-refresh every 5s) → task console
- Module selector, args input, Dispatch, task history with status colour coding
- Dark theme; Lock button wipes auth state

**Checkpoint:** ✅ All baseline tests verified:
- `make docker-secrets && make docker-up && make docker-provision && make client` → login returns bearer token ✅
- Implant check-in registers new session in `implant_sessions` table ✅
- gRPC `ListSessions` returns registered sessions to the client UI ✅
- `TaskSession` task queued via client is picked up by implant on next check-in ✅
- `proc_list` output displays as ASCII process tree in client ✅
- `sysinfo` output displays with memory bar and uptime formatting in client ✅
- Jitter bounds verified: 20 sleep cycles stay within `base ± jitter_pct%` ✅
- Redirector forwards matching URIs to server (profile URI mapping) ✅
- Redirector blocks requests with wrong or missing `x-wraith-redirector-token` → 403 ✅
- Redirector returns 404 for unmatched URIs when no decoy configured ✅
- `last_seen` timestamps reflect host timezone (e.g. `+0200` for CEST) ✅

---

### Step 2 — mTLS Foundation

Replace password auth with mutual TLS. This is the security bedrock everything else relies on.

**2.1 CA generation**
- On first server start, if no CA exists in the database, generate a self-signed CA using `rcgen`
- CA private key is stored encrypted in Postgres (AES-256-GCM, key derived from a startup passphrase via Argon2id + HKDF)
- CA cert is stored in plaintext in Postgres and exported to `/run/secrets/ca.crt` for clients

**2.2 Operator cert provisioning**
- CLI subcommand: `wraith-server provision-operator <username> <role>`
- Generates a leaf cert signed by the CA with the username and role in the Subject
- Outputs a `.p12` bundle shown once and never stored on the server (only the public cert is retained)
- Operator imports the `.p12` into their keychain or hardware token

**2.3 mTLS on gRPC**
- Server's tonic gRPC listener: configure `rustls` with the CA as the only trusted root; require client cert
- Client cert's Subject CN is extracted and used as the operator identity; no username/password needed
- Replace `Login` RPC with cert validation; tokens are eliminated entirely
- CRL table in Postgres: on every connection, check the cert serial against the CRL before accepting

**2.4 mTLS for redirector ↔ server**
- Redirector provisioning CLI: `wraith-server provision-redirector <name>` issues a redirector cert
- Redirector presents this cert on its upstream connection to the server
- Server rejects any upstream connection without a valid redirector cert

**2.5 Operator cert lifecycle**
- `wraith-server revoke-operator <username>`: adds cert serial to CRL; takes effect on next connection attempt with zero downtime
- `wraith-server revoke-redirector <name>`: same for redirectors
- Certs are valid for 7 days (operators) / 30 days (redirectors) by default; rotated via re-provisioning

**Checkpoint:** Operator connects with `.p12`; server rejects any connection without a valid signed cert; revoking a cert immediately terminates that operator's next connection attempt.

---

### Step 3 — Server Hardening

**3.1 Credential storage**
- Operator password field removed entirely (cert-only auth); Argon2id used only for the CA key encryption passphrase
- Loot/credential vault: AES-256-GCM, per-engagement key derived from a master passphrase entered at startup; master key lives in process memory only, never stored
- On shutdown, master key is zeroed (`zeroize` crate)

**3.2 Audit log**
- Append-only `audit_log` table in Postgres: `(id, operator, action, session_id, task_id, timestamp, prev_hmac, hmac)`
- Each row's HMAC covers `prev_hmac || operator || action || timestamp` using a key derived from the master passphrase
- Any tampered row breaks the chain; the audit log viewer highlights broken chains

**3.3 Rate limiting and hardening**
- `tower` middleware: implant check-ins capped at 60/min per IP; operator gRPC at 10/min per IP
- All HTTP API endpoints enforce `Content-Type: application/json`
- Request body size limit: 10 MB default, configurable per endpoint
- Server version string not exposed in any response header
- gRPC bound to `127.0.0.1:50051` only; HTTP implant endpoint bound to `0.0.0.0:8080` (or via redirector)

**3.4 RBAC**
- Roles: `admin`, `operator`, `viewer`
- Admins: provision/revoke certs, create engagements, see all sessions
- Operators: task sessions they are assigned to, access loot for their assignments
- Viewers: read-only access to sessions and task history
- Role encoded in operator cert Subject; verified on every gRPC call

**3.5 Session locking**
- `session_locks` table: only one operator can task a session at a time
- `AcquireSessionLock` / `ReleaseSessionLock` RPCs
- Lock auto-expires after 30 minutes of inactivity

**3.6 Error handling**
- All `unwrap()` / `expect()` replaced with `?` propagation or explicit error variants
- Auth failures return identical response bodies and take identical time (constant-time comparison via `subtle` crate)
- Any unexpected error in a security-critical path returns 500 and logs internally; no stack traces in responses

**3.7 Real-time event streaming**
- `StreamEvents(Empty) → stream EventNotification` gRPC server-streaming RPC
- Event types: `new_session`, `session_lost`, `task_completed`, `burn_alert`, `redirector_degraded`, `artefact_created`
- Client subscribes on login; updates sessions table and alert feed live without polling
- Events persisted to `event_log` table; stream replays the last 100 on connect

**3.8 Listener management**
- `listeners` table: `(id, name, type, bind_addr, profile, status, created_at)`
- `CreateListener` / `DeleteListener` / `ListListeners` RPCs
- Server starts/stops the corresponding HTTP listener without restarting the process
- Operator UI shows each listener with session count and check-in rate

**3.9 REST API and webhook notifications**
- Documented REST API on a separate port (`/v1/...`) for external tool integration
- API key auth (separate from operator mTLS); scoped to read-only or read-write
- Webhook table: `(id, url, events, hmac_secret, enabled)`; `POST` to the URL on matching events (new session, task completed, burn alert)
- Delivery is best-effort with 3 retries; failures logged but do not block the event pipeline
- Slack/Teams/Discord webhooks supported via the same mechanism (JSON body formatted per-platform)

**3.10 Payload generator**
- `BuildPayload` RPC: operator specifies target OS/arch, profile, kill date, working hours, and optional staging
- Server runs `cargo build --release -p implant` in a sandboxed container with the requested compile-time env vars set
- Output: binary bytes streamed back to the operator; never written to the server's filesystem
- Build container is ephemeral; no build artefacts remain after the stream completes

**Checkpoint:** Revoke a cert mid-session → connection dropped on next call. Two operators cannot queue tasks to the same session simultaneously. Live event stream delivers a new-session notification within 1 second of check-in.

---

### Step 4 — Docker Hardening

**4.1 Production Dockerfile** ✅
- 4-stage build: planner → dependency cache (cargo-chef) → builder → `debian:bookworm-slim` runtime
- Non-root `wraith` user; `ca-certificates` + `libssl3` only
- `HEALTHCHECK` via `/proc/1/status`

**4.2 Docker Compose** ✅
- `restart: unless-stopped`, Docker secrets, named `pgdata` volume, internal-only network
- Postgres: no host port; server ports bound to `127.0.0.1` only
- Redirector: separate image, depends on server healthcheck, exposes `0.0.0.0:8443`
- ☐ `docker-compose.prod.yml` with resource limits and `json-file` log driver with size caps

**4.3 Implant cross-compilation** ☐
- `cross` for hermetic `x86_64-unknown-linux-musl` and `x86_64-pc-windows-gnu` builds
- Windows implant signed offline with `osslsigncode` using a locally-held Authenticode cert
- Linux implant optionally GPG-signed; detached `.sig` file kept alongside the binary
- Build happens on the operator machine; no third-party build infrastructure involved

**Checkpoint:** `make docker-up` brings the full stack up from zero. `make implant-linux` and `make implant-windows` produce statically-linked release binaries with no system dependencies.

---

### Step 5 — Redirector + Infrastructure OPSEC

**5.1 Complete the redirector** ✅ (partial)
- ✅ Profile-aware routing: requests matched against `http.checkin_uri` / `http.result_uri` from profile
- ✅ Unmatched requests proxied to `decoy_url` (404 if unset)
- ✅ Forwards `X-Wraith-Redirector-Token` header; strips hop-by-hop headers
- ✅ `--profile`, `--profiles-dir`, `--upstream`, `--listen`, `--token` CLI flags
- ✅ `WRAITH_REDIRECTOR_TOKEN` env var override (read from Docker secret via entrypoint)
- ☐ Unmatched requests return `301` to a legitimate domain instead of 404
- ☐ Upstream connection to server over mTLS (redirector cert)
- ☐ `tracing` level set to `error` in production (no access logs to disk)

**5.2 Malleable profiles** ✅
- ✅ Full `C2Profile` struct: `ProfileMeta`, `TransportConfig`, `HttpConfig`, `ServerConfig`
- ✅ `default-https.toml` and `jquery-malleable.toml`
- ☐ `uri_append_random` wired into implant beacon requests

**5.3 Redirector health monitoring** ☐
- Server polls each redirector every 60s via a localhost-only `/health` endpoint
- `degraded` after 3 missed polls; `offline` + operator notification after 10

**5.4 Burn detection** ☐
- `burn_alerts` table in Postgres
- `StreamEvents` delivers burn alerts in real time (see 3.7)
- Alert pauses task dispatch; operator must acknowledge before resuming
- Split-session alert: same session ID from two IPs within 5 minutes → suspect flag

**Checkpoint:** Take the redirector offline → server raises a burn alert within 2 minutes → operator sees it in the client → acknowledging resumes dispatch.

---

### Step 6 — Implant OPSEC

**6.1 Beacon hardening**
- Jitter: sleep = `base * (1.0 ± jitter_pct/100 * rand)` using a CSPRNG (`getrandom`)
- Kill date: compile-time constant; implant calls `std::process::exit(0)` cleanly if past kill date before any network activity
- Working hours mode: configurable time window; implant sleeps until the window opens
- Max check-in failures: after N consecutive HTTP failures, enter a long sleep (24h) before retrying; never hammer a burned endpoint

**6.2 Per-session encryption**
- On first check-in, implant generates an ephemeral X25519 keypair (using `x25519-dalek`); sends public key in check-in body
- Server generates its own ephemeral keypair; performs ECDH; derives per-session AES-256-GCM key via HKDF (`hkdf` crate)
- Server sends its public key back in `CheckinResponse`
- All subsequent task and result payloads are encrypted with this key before being placed in the HTTP body
- The outer TLS handles transport confidentiality; this layer survives SSL inspection proxies

**6.3 Response HMAC validation**
- Each server response includes an HMAC-SHA256 over the response body, signed with the per-session key
- Implant validates the HMAC before processing any task; invalid or missing HMAC → ignore + increment failure counter
- Prevents blue team from injecting fake tasks into a captured session

**6.4 Anti-sandbox (Linux first)**
- Uptime check: `/proc/uptime` < 600 seconds → sleep 60s and retry
- Process count: parse `/proc/` entries; < 20 processes → assume sandbox → exit
- Known sandbox indicators: check for `wireshark`, `strace`, `ltrace`, `tcpdump` in process list → exit
- Sleep acceleration: `sleep(1)`, measure wall time; if returned in < 100ms → exit
- All checks configurable at build time via feature flags; disabled in debug builds

**6.5 Staging architecture**
- Stage 0 stager: single source file, ~200 lines; connects to C2, fetches stage 1 as encrypted bytes, loads into memory, jumps to entry point
- Stage 1 full implant: separate binary compiled to a position-independent format; all modules live here
- Stage 0 is the only artifact delivered to the target; stage 1 never touches disk
- Stage 0 zeroes itself in memory after loading stage 1

**Checkpoint:** Implant survives an SSL inspection proxy (inner AES layer). Response with invalid HMAC is silently ignored. Implant exits cleanly on kill date.

---

### Step 7 — Additional Capabilities (Linux baseline)

**7.1 Streaming file transfers**
- Large `file_get` / `file_put` operations split into 512 KB chunks
- Each chunk is a separate task result so no single HTTP body exceeds the size limit
- Server reassembles chunks in order; client shows a progress bar

**7.2 File browser**
- `file_browser` module: recursive directory listing with metadata (size, mtime, permissions, owner)
- Output is structured JSON; client renders it as a tree view

**7.3 Screenshot module (Linux / X11)**
- Capture via X11 (`x11` crate) or Wayland (`pipewire` screenshot API)
- Output: base64 PNG; no temp file
- Client displays the screenshot inline as an image widget

**7.4 Linux privilege escalation enumeration**
- `privesc_linux` module: `sudo -l` output, SUID binary list, capabilities scan (`getcap -r /`), writable cron entries, writable PATH elements
- Returns a structured list of findings with severity labels

**7.5 Linux persistence**
- `persist_linux` module: `--action install|remove`, mechanisms:
  - `crontab`: user crontab entry with configurable schedule
  - `systemd`: `~/.config/systemd/user/` service unit; `systemctl --user enable`
  - `bashrc` / `zshrc` / `profile.d`: append exec stanza to shell init files
  - `ld_preload`: write a shared library to a writable path, add to `LD_PRELOAD` in shell init
  - `suid_abuse`: detect a writable SUID binary and plant a payload that executes on invocation
- On install, logs the artefact path and mechanism to the server's `artefacts` table for cleanup tracking
- On remove, deletes the artefact and marks it cleaned in the table

**7.6 SOCKS5 proxy**
- `socks5` module: starts a SOCKS5 listener on the implant host on a random port
- Traffic is tunnelled through the existing C2 channel as chunked task results
- Operator connects their tools through the server-side SOCKS endpoint

**7.7 Port forward**
- `port_fwd` module: bind a local port on the implant host, forward connections through the C2 channel to a specified remote host:port
- Useful for reaching internal services (SMB, RDP, internal web apps) from the operator workstation

**7.8 Keylogger**
- `keylog` module: `--action start|stop|dump`
- Linux: read from `/dev/input/event*` using `evdev`; buffer keystrokes in memory; upload on `dump`
- Windows (Step 12): `SetWindowsHookEx(WH_KEYBOARD_LL)`; same buffer-and-upload pattern
- Output never written to disk; buffer lives in implant memory only

**7.9 Browser credential dump**
- `browser_dump` module: extract saved passwords and cookies from Chrome and Firefox profiles
- Chrome: decrypt `Login Data` SQLite DB using the local AES key from `Local State`; on Linux key is in `gnome-keyring` or stored plaintext
- Firefox: decrypt `logins.json` using NSS / `key4.db`; invoke `nss` via FFI or shell out to `python3 -c` one-liner
- Output: structured JSON of `{url, username, password}` entries; never written to disk

**7.10 SSH lateral movement**
- `ssh_exec` module: connect to a remote host with harvested SSH credentials (password or key material passed as args)
- Execute a command and return stdout/stderr
- Optionally drop a copy of the implant on the remote host and execute it (staging the next session)

**Checkpoint:** Operator can browse the filesystem, stream a large file, capture a screenshot, SOCKS5-proxy through the implant, dump browser credentials, and install a persistent backdoor — all without touching disk beyond the initial implant binary.

---

### Step 8 — Alternative C2 Transports

Implement after the HTTP baseline is solid. Each transport is a selectable profile type; the implant picks its transport from the compiled-in profile.

**8.1 DNS C2**
- Encode outbound data as base32 labels in TXT query names; decode server responses from TXT records
- Chunk size: ≤ 63 bytes per label, ≤ 253 bytes total per query
- Requires a delegated subdomain (`c2.example.com`) with an authoritative NS record pointing at the server
- Use `trust-dns-resolver` (or raw UDP sockets) to avoid system resolver that may enforce `NXDOMAIN` policies
- Throughput is low (~1 KB/s); suitable for exfil-only or slow-burn operations in heavily filtered networks

**8.2 DNS-over-HTTPS (DoH)**
- Same encoding as 8.1 but tunnelled through HTTPS to a public DoH resolver (Cloudflare `1.1.1.1`, Google `8.8.8.8`)
- Indistinguishable from legitimate DoH traffic at the network layer
- Server-side: DNS listener decodes queries and proxies to the C2 pipeline

**8.3 WebSocket C2**
- `ws://` or `wss://` persistent bidirectional channel using `tokio-tungstenite`
- Eliminates polling latency; tasks delivered immediately without a check-in round trip
- Looks like a legitimate WebSocket upgrade to a web app; profile sets the `Host` header and upgrade path
- Fallback to HTTP polling if the WebSocket handshake fails

**8.4 HTTPS domain fronting (CDN)**
- TLS SNI: target CDN edge domain (e.g. `legit-site.com` on Cloudflare/Fastly/Akamai)
- HTTP `Host` header: the actual C2 domain configured as a backend origin rule on the CDN
- The TLS certificate seen by any proxy belongs to the CDN edge, not the C2 server
- Profile stores both the SNI host and the `Host` header separately; `reqwest` sets them independently

**8.5 Serverless fronting (cloud function relay)**
- Deploy an AWS Lambda / Azure Function / GCP Cloud Function that proxies requests to the real server
- Function URL is the implant's C2 address; function strips identifying headers before forwarding
- Terraform module (Step 11) provisions the function; Ansible (Step 10) rotates it
- The function's domain (`*.lambda-url.us-east-1.on.aws`) is nearly impossible to block without breaking AWS itself

**8.6 SMB named-pipe peer-to-peer**
- Implants in the same network segment can relay C2 traffic peer-to-peer over SMB named pipes
- One implant acts as the egress proxy (has outbound HTTP); others connect to it via `\\.\pipe\<random>`
- Uses Windows `CreateNamedPipe` / `ConnectNamedPipe`; no new network connections from the non-egress implants
- Server sees only one session per egress implant; the relay is transparent

**8.7 SaaS exfil channels**
- `exfil_slack` / `exfil_teams` / `exfil_discord`: POST results to a team webhook URL or bot API token
- `exfil_email`: SMTP or IMAP IDLE (poll inbox for tasks, send results as replies); useful in air-gapped-adjacent scenarios
- These channels are one-way-exfil by default; commands require a separate inbound mechanism
- Profile stores the API token / webhook URL encrypted with the per-session key

**8.8 Multiplexed transport selector**
- `transport_switch` command: operator instructs an implant to switch its active transport (e.g. HTTP → WebSocket → DNS) without losing the session
- Implant tries transports in priority order from the profile; falls back automatically on failure
- Session ID is preserved across transport switches; server detects the reconnect and merges the session

**Checkpoint:** Implant successfully beacons via DNS TXT queries with no direct TCP connection to the server. Domain-fronted traffic passes through a CDN without the CDN operator knowing the true destination.

---

### Step 9 — Artefact Tracking and Anti-Forensics

**9.1 Artefact table**
- `artefacts` table: `(id, engagement_id, session_id, module, description, path, status, created_at, cleaned_at)`
- Every module that creates a side effect (file write, registry key, scheduled task, cron entry) inserts a row
- Status: `pending`, `cleaned`, `ignored`

**9.2 Cleanup modules**
- `timestomp` module: overwrite file timestamps (`atime`, `mtime`, `ctime`) using `utimensat` syscall directly; stomp to match a reference file's times
- `log_clear` module (Linux): truncate `~/.bash_history`, `/var/log/auth.log`, `/var/log/syslog`; flush in-memory history via `HISTFILE=/dev/null`
- `shred` module: overwrite a file with random bytes N times before unlinking

**9.3 Engagement close checklist**
- `close_engagement` RPC: server checks for any `artefacts` rows with `status = pending`; returns a list if any are uncleaned
- Client shows a checklist; operator must mark each artefact or explicitly override before the engagement is closed

---

### Step 10 — Ansible Automation

**10.1 Project structure**

```
ansible/
├── inventory/
│   └── hosts.yml.example        # VPS IPs, SSH keys
├── roles/
│   ├── common/                  # OS hardening: unattended-upgrades, ufw, fail2ban, sshd hardening
│   ├── docker/                  # Docker CE install, daemon.json hardening
│   ├── wraith-server/           # Copy compose files, secrets, start stack
│   ├── redirector/              # nginx reverse proxy + TLS, redirector container
│   ├── monitoring/              # Prometheus + Grafana + log shipping
│   └── jumpbox/                 # WireGuard VPN: generate keys, wg0.conf, systemd unit
├── deploy.yml                   # Full server stack: common + docker + wraith-server
├── deploy-redirector.yml        # New redirector: common + docker + redirector
├── rotate-redirector.yml        # Spin up new redirector, register cert, destroy old
├── teardown.yml                 # Revoke all certs, wipe secrets, destroy VPS
└── group_vars/
    └── all.yml                  # Non-secret config (ports, paths, versions)
```

**10.2 Role: common**
- UFW: deny all inbound by default; allow SSH on a non-standard port; allow only expected service ports
- `fail2ban`: SSH and nginx jails
- `unattended-upgrades`: security updates only; no automatic reboots
- Harden `sshd_config`: `PermitRootLogin no`, `PasswordAuthentication no`, `AllowUsers deploy`
- Create a non-root `deploy` user with SSH key auth only

**10.3 Role: wraith-server**
- Copy `docker-compose.prod.yml` and `docker/` to `/opt/wraith/`
- Create secret files at `/opt/wraith/secrets/` with correct permissions (`chmod 600`)
- Pull images, start the stack via `docker compose up -d`
- Register a `systemd` service unit that restarts the stack on boot

**10.4 Role: redirector**
- Install nginx, configure as a reverse proxy to the redirector container
- Configure TLS: Let's Encrypt via `certbot` (ACME HTTP-01 or DNS-01 challenge); auto-renew via systemd timer
- Issue the redirector mTLS cert via `wraith-server provision-redirector` (run against the server API)
- Configure UFW to allow port 443 from any; deny 80 except for ACME challenges

**10.5 Role: monitoring**
- Deploy Prometheus scraping the server's `/metrics` endpoint (exposed on localhost only)
- Deploy Grafana with a pre-provisioned dashboard: active sessions, task throughput, check-in rate, error rates, redirector health
- Deploy Loki + Promtail for structured log aggregation; logs never written to redirector disk
- All monitoring services bound to `127.0.0.1`; accessible via WireGuard only

**10.6 Role: jumpbox**
- Generate WireGuard keypair; configure `wg0.conf` with the operator's public key as a peer
- `systemd-networkd` or `wg-quick` to bring up the interface on boot
- UFW: allow WireGuard UDP port; drop all other inbound
- Output the operator's WireGuard client config as a task fact

**10.7 Makefile integration**
```makefile
infra-up:          ansible-playbook ansible/deploy.yml -i ansible/inventory/hosts.yml
infra-redirector:  ansible-playbook ansible/deploy-redirector.yml -i ansible/inventory/hosts.yml
infra-rotate:      ansible-playbook ansible/rotate-redirector.yml -i ansible/inventory/hosts.yml
infra-burn:        ansible-playbook ansible/teardown.yml -i ansible/inventory/hosts.yml --extra-vars "target=$(HOST)"
```

**Checkpoint:** `make infra-up` on a fresh Ubuntu 24.04 VPS takes the server from zero to running in under 10 minutes. `make infra-burn` revokes all certs and wipes all traces in under 5 minutes. Grafana dashboard shows live session data.

---

### Step 11 — Terraform Infrastructure

**11.1 Project structure**

```
terraform/
├── modules/
│   ├── vps/           # Parameterised VPS module (DigitalOcean, Linode, Vultr backends)
│   ├── dns/           # DNS zone + A record + subdomain delegation
│   └── cdn-front/     # Cloudflare worker or CDN origin rule for domain fronting
├── environments/
│   ├── dev/           # Single VPS, no CDN
│   └── prod/          # Server VPS + N redirector VPSes + CDN + DNS
├── main.tf
├── variables.tf
└── outputs.tf          # Output: server IP, redirector IPs, WireGuard config
```

**11.2 State management**
- State stored locally in `terraform/environments/<env>/terraform.tfstate`; never in Terraform Cloud
- State file encrypted at rest with `terraform-state-encrypt` or GPG-encrypted S3 backend using a local key
- `.gitignore` includes `*.tfstate`, `*.tfvars` (secrets), `.terraform/`

**11.3 Automated redirector provisioning**
- `vps` module accepts a `count` variable; spinning up N redirectors is a single `terraform apply`
- After apply, a `generate_inventory.py` script reads `terraform output -json` and writes `ansible/inventory/hosts.yml` automatically
- Redirector VPS uses a random hostname and is registered with the CDN module; no reference to "wraith" or "c2" in any DNS record

**11.4 Makefile integration**
```makefile
tf-plan:    cd terraform/environments/prod && terraform plan
tf-apply:   cd terraform/environments/prod && terraform apply
tf-destroy: cd terraform/environments/prod && terraform destroy
```

**11.5 Engagement provisioning flow**
1. `make tf-apply` → VPS IPs and CDN origins appear in Terraform outputs
2. `make infra-up` → provision and configure all hosts (inventory auto-generated from Terraform output)
3. `make infra-redirector` → provision redirectors with mTLS certs and TLS certificates
4. Engagement is live; all infrastructure reproducible from code + secrets

---

### Step 12 — Windows Capabilities

Implement after the Linux baseline is solid and tested in a real environment.

**12.1 Windows modules**
- `screenshot_windows`: BitBlt screen capture → base64 PNG; no temp file
- `registry`: read/write/delete Windows registry keys via `winreg` crate
- `clipboard_windows`: read clipboard via `OpenClipboard` / `GetClipboardData`
- `service_control`: start/stop/create/delete Windows services via `OpenSCManager`; enumerates running services
- `browser_dump_windows`: Chrome — decrypt `Login Data` using DPAPI key from `Local State`; Firefox — same NSS approach as Linux

**12.2 Process injection**
- `proc_inject`: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (classic baseline)
- `proc_inject_apc`: NtQueueApcThread early-bird variant (less monitored than CreateRemoteThread)
- `proc_hollow`: spawn a suspended legitimate process (e.g. `svchost.exe`), unmap its image, write payload, resume
- PPID spoofing: `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` set on the sacrificial process to appear as a child of Explorer or another trusted parent
- Sacrificial process pattern: risky operations (injection targets, credential access) run in a disposable child; kill the child on completion; parent implant survives

**12.3 BOF and reflective loading**
- `bof_exec`: load and execute COFF/BOF objects in-process without spawning a new process; compatible with Cobalt Strike BOF format
- `reflective_dll`: load a DLL from memory (position-independent reflective loader) without writing to disk or calling `LoadLibrary`
- `dotnet_exec`: host the CLR via `ICLRRuntimeHost` and execute a managed `.NET` assembly passed as bytes; no `Assembly.Load` from disk

**12.4 Token operations**
- `token_list`: enumerate tokens in running processes via `OpenProcessToken` + `GetTokenInformation`
- `token_steal`: impersonate a stolen token via `ImpersonateLoggedOnUser`; subsequent tasks run in the context of the stolen identity
- `make_token`: `LogonUser` to create a token from stolen credentials without needing a running process to steal from
- `dpapi_decrypt`: decrypt DPAPI blobs (Chrome master key, credential blobs, certificate private keys) using the current user's master key; optionally using a domain backup key for offline decryption

**12.5 Credential harvesting**
- `lsass_dump`: direct syscall (`NtReadVirtualMemory`) to avoid `MiniDumpWriteDump` hooks; stream output to server without writing to disk; process in server to extract hashes
- `sam_dump`: VSS + `reg save HKLM\SAM` approach; clean up shadow copy after; parse SAM/SYSTEM offline on the server

**12.6 Lateral movement**
- `wmi_exec`: lateral movement via `Win32_Process.Create` over WMI (DCOM transport); no SMB or PsExec; runs command in the context of a provided credential
- `dcom_exec`: lateral movement via DCOM using `MMC20.Application` or `ShellBrowserWindow` — no authentication dialog, no network share
- `ssh_exec_win`: same as Step 7.10 but compiled for Windows; uses `ssh2` crate or shells out to `plink.exe`/`ssh.exe`

**12.7 Windows persistence**
- `persist_windows` module: `--mechanism {run_key, scheduled_task, wmi_subscription, com_hijack, startup_folder}`, `--action {install, remove}`
  - `run_key`: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `scheduled_task`: XML-based task via `ITaskService` COM interface
  - `wmi_subscription`: permanent WMI event subscription triggered on logon or timer
  - `com_hijack`: override a per-user CLSID in `HKCU\Software\Classes\CLSID\` to point at a payload DLL
  - `startup_folder`: drop a `.lnk` shortcut in `shell:startup` (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`)
- All mechanisms log artefacts to the server for cleanup tracking

---

### Step 13 — Evasion

Build evasion only after you have a reliable, working, tested codebase. A broken sleep mask
produces crashes indistinguishable from detections. Every step here requires a Windows test VM
with a hypervisor snapshot workflow — test, detect, roll back, fix, repeat.

**13.1 API unhooking**
- Map a clean copy of `ntdll.dll` from `\KnownDlls\ntdll.dll` (kernel-maintained, unhooked) over the in-process ntdll text section
- Restores all EDR/AV userland hooks in one operation at startup

**13.2 Direct syscalls**
- HellsGate pattern: walk the ntdll export table at runtime to resolve syscall numbers (SSNs)
- Generate inline `syscall` stubs for all sensitive calls: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtReadVirtualMemory`, `NtQuerySystemInformation`
- No userland ntdll dependency for any security-sensitive operation

**13.3 Stack spoofing**
- Before any suspicious call: walk the current thread's stack, replace return addresses with addresses inside legitimate modules
- Restore original addresses after the call returns
- Defeats EDR stack-walk detectors that flag unbacked (non-module) memory return addresses

**13.4 AMSI and ETW bypass**
- Patch `AmsiScanBuffer` in-process to return `AMSI_RESULT_CLEAN` before any scripting engine is loaded
- Zero the first bytes of `EtwEventWrite` to suppress ETW telemetry from the implant process
- Re-apply after any unhooking that would restore them

**13.5 Sleep mask**
- Ekko pattern: `NtContinue` + ROP chain to:
  1. Encrypt implant heap (AES-128 key stored only in registers during sleep)
  2. Encrypt text section
  3. Mark memory `PAGE_NOACCESS`
  4. Wait for sleep timer
  5. Restore permissions, decrypt, resume
- After wake-up: verify text section integrity before resuming (detect EDR patching during sleep)
- No RWX memory at any point

**13.6 PE obfuscation (build-time)**
- Build script (`implant/build.rs`): XOR-encrypt all string literals with a per-build random key
- Runtime: decrypt inline on first use, re-encrypt after
- Import resolution by hash (djb2): no import table to inspect
- Section names randomised; Rich header overwritten with plausible legitimate compiler values
- Every build produces a unique binary; no two implants share a byte pattern

**13.7 PE stomping**
- Instead of allocating new `RWX` memory, overwrite an existing legitimate module's already-mapped memory region with the payload
- The memory region appears backed by a legitimate on-disk PE; memory scanners see a known module path
- Target: a large, infrequently-called system DLL (`wbemcomn.dll`, `msdmo.dll`)

**13.8 Floating code (Gargoyle variant)**
- Payload memory marked `PAGE_NOACCESS` between executions; a timer APC fires, marks it `PAGE_EXECUTE_READ`, runs a short stub, re-marks `PAGE_NOACCESS`
- Memory is invisible to tools that walk `VirtualQuery` while the implant is sleeping
- No RWX at any point; the execute permission exists for < 1ms per beacon cycle

**13.9 DLL side-loading**
- Place a malicious DLL with a legitimate filename next to a signed executable that imports it
- The signed executable is then run by the user or a scheduled task; Windows resolves the DLL from the application directory first
- No process injection; no suspicious `CreateRemoteThread`; the signed binary is the loader

**13.10 Heaven's Gate (32-bit implant)**
- Compile a 32-bit implant that transitions to 64-bit mode to issue native 64-bit syscalls
- Bypasses 32-bit userland hooks entirely (most EDRs only hook the 32-bit ntdll)
- Useful for targeting 32-bit application processes running on 64-bit Windows

---

### Step 14 — Operator GUI (full implementation)

Build the full GUI after the server API is stable. Each view maps directly to server RPCs.

**14.1 Auth screen**
- Certificate picker (OS keychain or file selector)
- mTLS handshake via `rustls`; on failure show the error and stay on the auth screen
- On success, store the gRPC channel in app state; navigate to Dashboard

**14.2 Dashboard**
- Stat cards: Active Sessions, Burn Alerts, Pending Tasks, Uncleaned Artefacts
- Burn alert feed: prominent, above all other content; each alert shows redirector, affected sessions, recommended action
- Recent events feed: live `StreamEvents` gRPC stream
- Infrastructure health panel: each redirector with check-in frequency sparkline and cert expiry countdown

**14.3 Sessions view** ✅ (partial)
- ✅ Table: hostname, user, OS/arch, IP, last seen, active indicator
- ✅ Click to select session; task console opens below
- ☐ Full column set: Transport, Tags, Operator
- ☐ Right-click context menu (File Browser, Process Manager, Rotate Transport, Kill, Flag as Suspect)
- ☐ Suspect flag pauses task dispatch
- ☐ Per-session tags and operator notes (freeform text stored in `session_metadata` table)

**14.4 Session console** ✅ (partial)
- ✅ Module selector, args input, Dispatch button
- ✅ Task history (last 30), status colour coding, stdout extraction
- ☐ Tabbed, one tab per open session
- ☐ OPSEC rating label per module (Low / Medium / High)
- ☐ Rendered output for `proc_list` (table), `screenshot` (image), `sysinfo` (key-value), `file_browser` (tree)
- ☐ Task templates: save a module + args as a named shortcut; one-click dispatch

**14.5 Interactive shell**
- True PTY (pseudoterminal) over the C2 channel: `pty` crate on Linux, `ConPTY` API on Windows
- Implant spawns a shell process inside a PTY; bytes flow bidirectionally through C2 task/result messages
- Client renders the terminal using `egui`'s text drawing with ANSI escape code support
- Tab completion, arrow-key history, and Ctrl-C/Ctrl-D forwarded as raw bytes

**14.6 File editor**
- `file_editor` view: fetch the remote file, open in a VIM-keybinding text editor widget
- On save: diff the edited content against the original; only the changed bytes are sent back via `file_put`
- Handles binary detection; refuses to open files > 10 MB in the editor (offers streaming download instead)

**14.7 Infrastructure view** ☐
- All redirectors: status, check-in rate, mTLS cert expiry countdown, burn status
- One-click burn action: revoke cert + remove from profile + trigger Ansible teardown
- Transport selector: switch a session's active transport from the GUI

**14.8 Artefact and cleanup view** ☐
- Timeline of artefacts; Pending / Cleaned / Ignored status
- "Generate cleanup task" dispatches the remove module to the session
- Engagement close checklist: blocked until all artefacts resolved

**14.9 Session graph** ☐
- Visualise network topology: implant sessions as nodes, redirectors as relay nodes, lateral movement edges
- Node colour: active (green), inactive (grey), suspect (amber), burned (red)
- Hover to see session details; click to open session console

**14.10 Supporting views** ☐
- **Loot / Credentials**: structured table of harvested credentials per engagement; searchable; copy-to-clipboard
- **Screenshots gallery**: thumbnails, click to expand; sorted by session and timestamp
- **Payload Builder**: GUI front-end for Step 3.10 `BuildPayload` RPC; profile picker, kill date, architecture selector
- **Operators**: list active operators, their cert expiry, current sessions, force-disconnect
- **Audit Log**: paginated log viewer with chain-integrity indicator; filter by operator, session, action
- **MITRE ATT&CK heatmap**: colour-coded matrix showing which techniques have been used in the current engagement

**14.11 Multi-pane layout and theming**
- Split view: sessions list + active session console + task history side by side
- Adjustable pane sizes; layout persisted to `~/.config/wraith/layout.json`
- Switchable colour themes (dark default, light, high-contrast); stored per user preference
- Operator chat panel: in-band messaging between concurrent operators via a `SendMessage` / `StreamMessages` RPC pair; messages are ephemeral (not persisted)

---

## Dependency Graph

```
✅ Step 1 (baseline: DB, gRPC, beacon, client)
    │
    ├──► Step 2 (mTLS)
    │        │
    │        ├──► Step 3 (server hardening: audit log, RBAC, vault, streaming, payload builder)
    │        │
    │        └──► Step 5 (redirector hardening + burn detection)
    │
    ├──► Step 4 (Docker hardening + offline signing)  ← partial ✅; prod compose + cross-compile remaining
    │
    ├──► Step 6 (implant OPSEC: kill date, HMAC, X25519, anti-sandbox, staging)
    │        │
    │        ├──► Step 7 (capabilities: files, screenshot, SOCKS5, keylogger, browser dump)
    │        │        │
    │        │        ├──► Step 8 (alternative transports: DNS, WebSocket, fronting, SMB P2P)
    │        │        │
    │        │        └──► Step 9 (artefact tracking + anti-forensics)
    │        │
    │        └──► Step 12 (Windows capabilities)  ← after Linux baseline
    │                 │
    │                 └──► Step 13 (evasion)  ← only after Steps 1–12 are solid + tested
    │
    ├──► Step 10 (Ansible)  ← after Step 4
    │        │
    │        └──► Step 11 (Terraform)
    │
    └──► Step 14 (full GUI)  ← partial ✅; advanced views remaining
```

**Rule at every step:** Ask "what happens when this component is burned or compromised?"
If the answer is "the operator is exposed" or "other engagements are affected", the design is wrong.
Fix the isolation before moving on.

---

## Technology Reference

| Concern | Crate / Tool |
|---|---|
| HTTP server | `axum` |
| gRPC | `tonic` + `prost` |
| TLS / mTLS | `rustls` + `tokio-rustls` + `rcgen` |
| Database | `sqlx` (postgres) |
| Crypto — symmetric | `aes-gcm` |
| Crypto — asymmetric | `x25519-dalek`, `rcgen` |
| Crypto — hashing | `argon2`, `hmac`, `sha2`, `hkdf` |
| Secrets zeroing | `zeroize` |
| Timing attacks | `subtle` |
| RNG | `getrandom`, `rand` |
| HTTP client (implant) | `reqwest` (rustls backend, no native-tls) |
| WebSocket | `tokio-tungstenite` |
| DNS | `trust-dns-resolver` |
| PTY (Linux) | `pty` crate |
| PTY (Windows) | `ConPTY` Windows API |
| Serialisation | `serde` + `serde_json` |
| GUI | `eframe` / `egui` |
| Config files | `toml` + `serde` |
| CLI parsing | `clap` |
| Async runtime | `tokio` |
| Logging | `tracing` + `tracing-subscriber` |
| Metrics | `prometheus` (server-side scrape endpoint) |
| Log aggregation | `loki` + `promtail` (via Ansible role) |
| Cross-compilation | `cross` (Docker-based) |
| Code signing | `osslsigncode` (Windows), GPG (Linux) |
| Infrastructure | Ansible, Terraform, Docker Compose |
