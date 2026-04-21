# Wraith C2 — Implementation Plan

**Core philosophy:** Assume every piece of infrastructure will eventually be identified.
Design every layer so that when it is burned, the damage is contained, the operator is
not exposed, and operations can resume from a clean slate within minutes.
Security is not a phase — it is the foundation every other decision is built on.

---

## OPSEC principles

Every decision in this plan follows these rules. When in doubt, the more conservative option wins.

1. **Assume burn** — every IP, domain, and certificate will eventually be identified. Design so that when it happens, the operator is not exposed and operations resume within minutes.
2. **Compartmentalise** — one engagement cannot affect another. One burned redirector cannot reveal the server. One compromised operator cert cannot compromise others.
3. **Minimal footprint** — never write to disk if memory works. Never spawn a process if in-process works. Never leave an artefact that isn't tracked for cleanup.
4. **Fail closed** — when anything is uncertain (sandbox, honeypot, unexpected response), the implant does nothing and sleeps rather than proceeding.
5. **No plaintext secrets anywhere** — not in env vars, not in logs, not in database columns, not in HTTP responses. Credentials are hashed or encrypted at rest; keys live only in process memory.
6. **Operator is not the server** — the operator's machine never has a direct network path to the C2 server. At least one layer of indirection (VPN, jump box) sits between them at all times.

---

## Phase 1 — Hardened Foundation

Everything else is built on top of this. No capabilities until this is solid.

### 1.1 mTLS everywhere

**Operator ↔ server (gRPC):**
- Generate a per-deployment CA at first run using `rcgen`; CA private key never leaves the server
- Server issues operator certificates signed by the CA; operators authenticate with their cert, not a password
- Certificate revocation list (CRL) stored in Postgres; revoke a compromised operator cert without restarting
- gRPC transport uses `rustls` with the deployment CA as the only trusted root — no system CAs

**Server ↔ redirector:**
- Redirector gets its own certificate signed by the same CA
- Server rejects any connection that does not present a valid redirector cert
- Redirectors cannot be used to exfiltrate data even if compromised — they only relay, never store

**Why:** Plaintext gRPC means any network observer between the operator and server can read all tasking. mTLS means even if the server IP is burned and monitored, the traffic is opaque.

### 1.2 Operator authentication overhaul

- Remove username/password login entirely for production deployments
- Operators authenticate exclusively via their mTLS client certificate
- Certificates include the operator's username and role in the Subject
- Tokens are eliminated — the cert IS the credential; no token to steal from memory
- `provision-operator <username> <role>` generates a certificate bundle (`.p12`) shown once; server stores only the public cert

### 1.3 Server hardening

- Bind gRPC to `127.0.0.1` by default; only expose it through an mTLS-terminating reverse proxy
- HTTP implant endpoint is the only surface exposed externally, and only via a redirector
- No database port ever exposed outside the container network (already enforced by Docker Compose)
- All Postgres credentials injected via Docker secrets (already implemented)
- Add rate limiting on all HTTP endpoints: login attempts capped at 5/min per IP, implant check-ins at 60/min per IP
- Enforce `Content-Type: application/json` on all API endpoints to prevent CSRF-style abuse
- Add request size limits to prevent large-body DoS

### 1.4 Credential storage hardening

- Operator password hashes use Argon2id with tuned parameters (time=3, memory=64MB) — already using Argon2, tune the parameters
- Loot credentials stored encrypted at rest using a per-engagement AES-256-GCM key derived from a master key that is never stored in the database
- The master key lives only in the server process memory, derived from a passphrase entered at startup
- On server shutdown the key is zeroed; credentials are inaccessible without restarting and re-entering the passphrase
- Audit log is append-only and tamper-evident: each row contains an HMAC of the previous row's content

### 1.5 Minimal attack surface

- Remove all unused workspace crates and dependencies; run `cargo +nightly udeps` on every PR
- No debug endpoints, no `/health` that reveals version, no stack traces in HTTP responses
- Server version string is not exposed in any response header
- Remove `tokio-stream` from server if unused; every unused dep is a potential CVE

### 1.6 Error handling and fail-closed behaviour

- All authentication failures return the same response body and take the same time (constant-time comparison, uniform error message) to prevent user enumeration
- Any unexpected error in a security-critical path (auth, crypto) panics the request handler and returns 500 — never partially succeeds
- Replace all `unwrap()` / `expect()` calls with proper propagation; a panic in production is a crash, not a silent corruption

### 1.7 Tests

- Unit tests for every crypto path: password hashing, token comparison, cert validation
- Integration test: full mTLS handshake between a test client and the server using a generated cert bundle
- Fuzz the HTTP handlers with `cargo-fuzz` targeting the JSON deserialisers
- `make test` runs everything; CI blocks merges on any failure

---

## Phase 2 — Infrastructure OPSEC

The server IP and domain are the most burned assets. Design for rapid rotation and maximum separation between the operator and the infrastructure.

### 2.1 Redirector hardening

- Redirectors only forward requests that match an exact allowlist of URI patterns from the active profile
- Any request that does not match returns a `301` to a legitimate website (e.g. Microsoft, Cloudflare) — blue team scanning the redirector sees nothing suspicious
- Redirectors log nothing to disk; all access logs are discarded
- Redirector health is monitored by the server; if a redirector stops responding it is automatically marked offline and operators are notified
- Add a `block_list` to the profile: requests from known security vendor IP ranges are silently dropped and redirected

### 2.2 Domain strategy

- Use aged domains (registered 6+ months before use) with matching WHOIS history
- Categorise domains as business-relevant (finance, technology, logistics) before the engagement using domain categorisation services
- Separate domains per engagement and per redirector — never reuse
- Domain fronting: configure a CDN in front of the redirector so the SNI hostname is a legitimate CDN domain and the C2 domain is only in the HTTP `Host` header
- Implement automatic domain rotation: if the server detects a redirector is being blocked (0 check-ins for N minutes from a previously active implant), it rotates implants to a fallback domain via a secondary channel

### 2.3 Fallback channels

- Every implant is compiled with a primary and up to three fallback C2 endpoints
- If the primary fails for N consecutive attempts, the implant automatically tries the next endpoint
- Endpoints use different transports (HTTPS, DNS, WebSocket) so blocking one transport does not kill the session
- Fallback order and thresholds are configurable at build time via the payload builder

### 2.4 Burn detection

- The server tracks per-redirector check-in frequency; a sudden drop to zero from an active implant triggers a burn alert
- Burn alert: push notification to all connected operators, flag the redirector as potentially burned, pause new task dispatch to affected sessions
- Operators can acknowledge the burn and choose: rotate infrastructure, kill the session, or continue monitoring
- All implant traffic is tagged with a per-session nonce; if the same session ID appears from two different IPs simultaneously, raise a split-session alert (possible man-in-the-middle or blue team replay)

### 2.5 Infrastructure compartmentalisation

- Each engagement gets its own redirector, its own domain, and its own operator certificate
- The server is never directly reachable from the internet — always behind at least one redirector
- If one engagement's infrastructure is burned, it cannot be used to trace back to other engagements or to the server
- Operator VPN/Tor exit nodes are rotated between sessions; the server never sees the operator's real IP

### 2.6 Fast infrastructure rotation (Ansible)

- `ansible/` with roles: `redirector`, `wraith-server`
- `make infra-up` spins up a new redirector on a VPS, generates its mTLS cert, registers it with the server, and updates the active profile — under 5 minutes
- `make infra-burn <redirector-id>` revokes the redirector's cert, removes it from the profile, and destroys the VPS
- All VPS provisioning uses throwaway payment methods and no personally identifying information

### 2.7 TLS certificate OPSEC

- Never use Let's Encrypt for C2 domains — LE certificates are logged in Certificate Transparency logs, which blue teams actively monitor
- Use a commercial CA or a self-signed cert with a convincing subject (matching the domain's business persona)
- Certificate validity period: 90 days maximum; rotate before expiry
- HPKP (HTTP Public Key Pinning): implants pin the expected certificate fingerprint at build time; a cert mismatch aborts the connection rather than connecting to a potential MitM

---

## Phase 3 — Implant OPSEC

The implant is the most exposed component. Every execution decision should minimise its visibility.

### 3.1 Staging architecture

Split the implant into two stages to minimise the initial footprint on disk:

**Stage 0 (stager):** ~5 KB
- Single purpose: connect to the C2, retrieve the stage 1 shellcode, load it into memory, jump to it
- Contains no capability, no strings of interest beyond the C2 URL
- Immediately overwrites itself in memory after loading stage 1
- Short kill date: if stage 1 is not retrieved within 60 seconds, the stager exits cleanly

**Stage 1 (full implant):**
- Never written to disk; lives entirely in allocated memory
- Loaded reflectively by stage 0
- Contains all modules, beacon logic, and crypto material

### 3.2 Anti-sandbox and environment validation

Before doing anything, stage 0 validates the environment:

- **Uptime check**: if system uptime < 10 minutes, sleep and retry — sandboxes reset frequently
- **User interaction**: check that at least some mouse/keyboard events have occurred since boot (via `GetLastInputInfo` on Windows) — automated sandboxes rarely simulate user input
- **Process list sanity**: count running processes; fewer than 30 on Windows suggests a sandbox
- **Known sandbox processes**: check for `vmsrvc.exe`, `vboxservice.exe`, `wireshark.exe`, `procmon.exe`, `x96dbg.exe`, `fiddler.exe`, `charles.exe` and exit cleanly if found
- **Domain check**: if the machine is not domain-joined and the engagement requires domain targets, skip execution
- **Sleep acceleration test**: call `Sleep(1000)` and measure wall time; if it returns in under 100ms the sandbox is accelerating time
- **CPUID hypervisor bit**: detect virtualisation at the hardware level
- **Canary file/registry**: check for known blue team canary artefacts (honeytoken files, registry keys) and exit if found

All checks are configurable at build time so they can be tuned per engagement.

### 3.3 Callback hardening

- Jitter: sleep interval varies by ±30% by default (configurable); never a perfectly regular interval
- **Working hours only mode**: configurable time window (e.g. 08:00–18:00 Mon–Fri); implant sleeps outside this window to blend with legitimate business traffic
- **Kill date**: hard-coded expiry timestamp; implant exits cleanly after this date with no external trigger needed
- **Max check-in failures**: after N consecutive failed check-ins the implant enters a long sleep (24h) before retrying, rather than hammering a burned endpoint and generating alerts
- **Response validation**: every server response must include a valid HMAC signed with the per-session key; unsigned or invalid responses are ignored (prevents blue team injecting fake tasks into a captured session)

### 3.4 In-memory operation

- Stage 1 is never written to disk under any circumstance
- All module output is buffered in memory and sent in the next check-in; no temp files
- File operations (`file_put`) write directly via syscall without going through the Win32 file API where possible
- The implant's own PE header is zeroed in memory after loading (`pe_header_stomp`) so memory scanners cannot identify it by signature

### 3.5 Sleep mask (memory encryption while idle)

- While sleeping, the implant encrypts its own heap, stack, and text section using XOR with a per-session key
- Uses the Ekko pattern: `NtContinue` + ROP chain to encrypt, sleep, decrypt — no RWX memory required
- After decryption, verify integrity of the text section before resuming (detect tampering)
- The encrypted blob is indistinguishable from random data to a memory scanner

### 3.6 Execution OPSEC

- **Spawn-to process**: all post-exploitation tasks that need a child process spawn into a configurable legitimate process (`svchost.exe -k netsvcs`, `RuntimeBroker.exe`) instead of `cmd.exe` or `powershell.exe`
- **Fork-and-run vs in-process toggle**: operator selects per-task whether to run in a sacrificial process (crash-safe, isolated) or in-process (no new process creation event)
- **Command-line spoofing**: after spawning a sacrificial process, overwrite its command line in the PEB to show an innocuous string instead of the actual arguments

---

## Phase 4 — Operator Security

The operator's machine and connection are as much of an attack surface as the server.

### 4.1 Operator network path

- Operators connect to the server exclusively over a dedicated VPN (WireGuard) that terminates on a separate jump box, not directly on the C2 server
- The jump box has no other services; its only role is WireGuard termination
- Operator IP is never the same between sessions; rotate VPN exit node per engagement
- The C2 server firewall allowlists only the jump box IP for gRPC; all other IPs are dropped silently

### 4.2 Operator certificate lifecycle

- Certificates are generated offline on the operator's machine, not on the server
- The server receives only the public cert during provisioning — the private key never transits the network
- Certificate validity: 7 days maximum for active engagements; revoke immediately on engagement close
- Certificates are stored in the operator's OS keychain or a hardware token (YubiKey), not as files on disk
- Lost or suspected-compromised cert: revoke via `wraith-server revoke-operator <username>`; takes effect on next connection attempt with zero downtime

### 4.3 Session security

- gRPC sessions have a maximum duration of 8 hours; client must re-authenticate after expiry
- Idle sessions (no gRPC call for 30 minutes) are terminated server-side
- Each gRPC message includes a monotonically increasing sequence number; replay attacks are detected and rejected

### 4.4 Multi-operator isolation

- Operators can only see sessions they have been explicitly assigned to, unless they hold the `admin` role
- An operator cannot read another operator's task history or loot unless granted explicitly
- Task dispatch is logged with the operator identity and cannot be repudiated
- Two operators cannot simultaneously task the same session; a lock must be acquired first

---

## Phase 5 — Traffic OPSEC

C2 traffic must be indistinguishable from legitimate business traffic at every inspection point.

### 5.1 Malleable HTTP profiles

Each listener has an associated profile defining the full shape of every HTTP request and response:

- **URI patterns**: randomised from a pool of realistic paths (e.g. `/api/v2/sync`, `/update/check`, `/telemetry/batch`)
- **Headers**: match a real browser/application exactly — `User-Agent`, `Accept`, `Accept-Encoding`, `Cache-Control`, `X-Requested-With`
- **Body encoding**: data encoded as JSON, multipart form, or Base64 within a realistic-looking field name
- **Response shape**: server responds with a realistic JSON/HTML body; C2 data is embedded in a specific field or HTTP header
- **TLS fingerprint**: configure the TLS stack to produce a JA3 hash matching a common browser or application (Chromium, curl, Python requests)

### 5.2 Traffic timing

- Beacon interval jitter: ±30% by default, configurable up to ±80%
- Working hours mode: callbacks only during configured time windows
- Burst suppression: large task outputs are split across multiple check-ins with random delays between them to avoid sudden spikes in traffic volume
- **Long-haul sleep**: between active tasking periods the implant can be put into a multi-day sleep via operator command; no callbacks during this period

### 5.3 Protocol transport options

Each transport is selectable at build time and fallback-ordered at runtime:

| Transport | Blend-in target | Notes |
|---|---|---|
| HTTPS | Browser traffic | Default; profile-driven URI/header shaping |
| DNS-over-HTTPS | DoH resolvers | Tunnels through port 443; hard to block without breaking browsing |
| WebSocket | SaaS application traffic | Persistent connection; lower latency |
| DNS TXT | DNS resolver queries | Ultra low bandwidth; works behind strict firewalls |
| ICMP | Network monitoring traffic | Requires admin; last resort |
| SMB named pipe | Internal file sharing | Peer-to-peer between implants; no direct internet required |

### 5.4 Per-session traffic encryption

Independent of TLS (which the redirector terminates):

- On first check-in the implant generates an ephemeral X25519 keypair and sends the public key
- Server generates its own ephemeral keypair and performs ECDH key exchange
- Resulting shared secret is used to derive a per-session AES-256-GCM key via HKDF
- All subsequent task and result data is encrypted with this key before being placed in the HTTP body
- Even if TLS is stripped by a MitM (e.g. corporate SSL inspection proxy), the C2 data remains encrypted

---

## Phase 6 — Capabilities

Core post-exploitation modules, built on top of the secure foundation.
Every module follows the same OPSEC rules: in-memory where possible, spawn-to for child processes, artefact cleanup built in.

### 6.1 Information gathering
- `sysinfo` — hostname, OS, arch, uptime, domain membership, logged-in users (already exists)
- `screenshot` — screen capture via BitBlt/X11; base64 PNG; no temp file
- `clipboard` — read clipboard contents
- `env` — dump environment variables
- `browser_dump` — extract saved credentials from Chrome/Firefox profile directories

### 6.2 Filesystem
- `file_get` / `file_put` — already exists; add streaming for large files to avoid single large HTTP body
- `file_browser` (ls) — directory listing with metadata
- `file_search` — recursive search by name pattern or content string; useful for finding config files, SSH keys, credential stores

### 6.3 Process operations
- `proc_list` — already exists
- `proc_kill` — kill by PID
- `proc_inject` (Windows) — shellcode injection into a remote process
- `execute_assembly` (Windows) — in-memory .NET via CLR hosting

### 6.4 Persistence
- Windows: registry Run key, scheduled task, WMI event subscription, COM hijacking
- Linux: crontab, systemd user unit, `.bashrc` hook
- All persistence modules accept `--action install|remove` and log the artefact to the server for cleanup tracking

### 6.5 Credential harvesting
- `lsass_dump` — LSASS memory via direct syscall (avoids `MiniDumpWriteDump` hook); stream output to server without writing to disk
- `sam_dump` — SAM + SYSTEM hive via VSS
- `keychain_dump` (macOS) — login keychain via Security framework
- `dcsync` — MS-DRSR `DsGetNCChanges` to pull any account's hashes from a DC

### 6.6 Active Directory
- `ad_enum` — full LDAP enumeration: users, groups, computers, SPNs, AS-REP targets, GPOs, ACLs, trusts
- `kerberoast` / `asrep_roast` — return encrypted tickets for offline cracking
- `bloodhound_collect` — BloodHound-compatible JSON collection
- `pass_the_hash` / `pass_the_ticket` / `golden_ticket` / `silver_ticket`
- `lateral_move` — unified lateral movement: SMB exec, WMI exec, PSRemote, DCOM exec

### 6.7 Privilege escalation
- Linux: sudo enum, SUID scan, capabilities scan, writable PATH/cron
- Windows: token list/steal, UAC bypass (fodhelper, eventvwr), named pipe impersonation
- macOS: TCC bypass enumeration, LaunchDaemon privilege paths

### 6.8 Tunnelling
- `socks5` — SOCKS5 proxy server inside the implant via tokio channels
- `port_fwd` — forward a specific remote port locally
- `smb_relay` — peer-to-peer relay between implants over SMB named pipes

### 6.9 Cloud and containers
- `cloud_meta` — query AWS/GCP/Azure IMDS for credentials and metadata
- `docker_escape` / `k8s_escape` — container escape via privileged container or `docker.sock`
- `k8s_enum` — enumerate Kubernetes secrets, pods, RBAC

---

## Phase 7 — Anti-Forensics

Clean up after every operation. Every artefact left behind is evidence.

### 7.1 Artefact tracking

The server maintains an `artefacts` table logging every side effect of every module: files written, registry keys created, processes spawned, scheduled tasks installed, WMI subscriptions registered.

At the end of an operation, the operator runs a cleanup checklist generated from this table.
Uncleaned artefacts are highlighted in the engagement report.

### 7.2 Cleanup modules

- `timestomp` — overwrite file timestamps (`Created`, `Modified`, `Accessed`) to match a reference file using `SetFileTime` / `utimensat`; also stomp the MFT `$STANDARD_INFORMATION` record to defeat MFT-based detection
- `log_clear` — clear Windows Event Log channels (Security, System, Application, PowerShell/Operational) via `EvtClearLog`; on Linux truncate auth.log, syslog, bash_history
- `prefetch_delete` — delete Windows Prefetch entries for executed binaries
- `shred` — securely overwrite a file before deletion (overwrite with random bytes N times, then delete)

### 7.3 Process cleanup

- After every BOF, reflective DLL, or assembly execution: unmap the allocation and zero the memory
- After every `proc_inject`: if the sacrificial process is no longer needed, kill it
- Before any long sleep: wipe heap regions containing sensitive strings (URLs, keys, operator names)

### 7.4 Network cleanup

- `dns_flush` — flush the DNS resolver cache after DNS C2 sessions
- `conn_hide` (Linux) — use `LD_PRELOAD` to hide the C2 connection from `ss` / `netstat`
- After engagement: remove all port forwards and SOCKS5 listener bindings

---

## Phase 8 — Evasion

Only after Phases 1–7 are solid. Evasion without a reliable, clean foundation creates
bugs that are indistinguishable from detections — you cannot tell if you are being caught
or if your own code is broken.

### 8.1 API unhooking

- On startup, remap `ntdll.dll` from `\KnownDlls\ntdll.dll` (a clean, unhooked copy maintained by the kernel) over the current process's `ntdll` text section
- This removes every userland hook an AV/EDR has installed
- Fallback: map a fresh copy from disk if `\KnownDlls` is not available

### 8.2 Direct syscalls

- HellsGate / Syswhisper3 pattern: walk the `ntdll` export table at runtime to resolve syscall numbers (SSNs)
- Emit inline `syscall` stubs for all sensitive calls: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtReadVirtualMemory`, `NtQuerySystemInformation`
- No dependence on userland `ntdll.dll` for any security-sensitive operation

### 8.3 Stack spoofing

- Before any suspicious API call, walk the stack and replace return addresses with addresses inside legitimate modules (`ntdll.dll`, `kernelbase.dll`)
- Restore original return addresses after the call returns
- Defeats EDR stack-walk detectors that flag calls originating from unbacked (non-module) memory

### 8.4 AMSI and ETW bypass

- Patch `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN` — applied in-memory before any scripting engine is loaded
- Zero the first bytes of `EtwEventWrite` to suppress ETW telemetry
- Both patches applied only in-process; no disk writes; re-applied after any unhooking operation that would restore them

### 8.5 Sleep mask (heap + text encryption)

- Ekko/Foliage pattern: before sleeping, use an APC chain to:
  1. Encrypt the implant's heap (RC4 or AES-128 with a random key stored only in registers)
  2. Encrypt the text section
  3. Mark memory as `PAGE_NOACCESS`
  4. Wait for the sleep timer
  5. Mark memory `PAGE_EXECUTE_READ`, decrypt text + heap, resume
- The implant is completely opaque to any memory scanner while sleeping
- After wake-up, verify text section integrity (detect EDR patching during sleep)

### 8.6 Process injection improvements

- Replace `CreateRemoteThread` with `NtQueueApcThread` (early-bird) — shellcode runs before the thread's main function
- PPID spoofing: create sacrificial processes with a spoofed parent PID using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
- Module stomping: write shellcode into an existing `PAGE_EXECUTE_READ` section of a legitimate module (e.g. a rarely-used `MUI` file mapped by a legitimate process) rather than allocating new RWX memory
- `RtlCreateUserThread` as an alternative to `CreateRemoteThread` — less monitored

### 8.7 PE obfuscation

- **String encryption**: all hardcoded strings (C2 URLs, module names, API names) are XOR-encrypted at compile time via a build script; decrypted inline at first use then re-encrypted
- **Import resolution by hash**: resolve all WinAPI imports at runtime by hashing the export name (djb2); no import table to inspect
- **Section randomisation**: PE sections are given random names; `.text` becomes a random 8-character string
- **Fake rich header**: overwrite the Rich header with plausible values matching a known legitimate compiler build
- **Compile-time polymorphism**: vary the XOR key and string layout on every build so no two implants have the same byte pattern

### 8.8 macOS-specific evasion

- **Dylib injection via `DYLD_INSERT_LIBRARIES`**: inject into processes at launch without ptrace
- **Gatekeeper bypass**: deliver via a signed container or an app bundle with a convincing structure; quarantine attribute removal after staging
- **Code signing**: sign the stager with an Apple Developer certificate if available; dramatically reduces Gatekeeper/XProtect scrutiny

### 8.9 Traffic-level evasion

- **JA3 fingerprint control**: configure the TLS client hello to match a target browser; Cloudflare, ZScaler, and most NGFWs fingerprint TLS at the JA3 level
- **HTTP/2**: use HTTP/2 for implant traffic; HTTP/2 is harder to inspect inline and produces a different network signature than HTTP/1.1
- **Certificate pinning**: implant pins the expected redirector certificate fingerprint; rejects any unexpected cert (blocks SSL inspection MitM and active response proxies)

---

## Phase 9 — Operator Client (GUI)

The GUI is built after the security foundation is solid. Every view reflects the security-first design.

### 9.0 Layout and chrome

```
┌─────────────────────────────────────────────────────────────┐
│  [≡] WRAITH     Sessions: 4 active    🔴 1 burn alert       │  ← top bar
├──────────┬──────────────────────────────────────────────────┤
│          │                                                   │
│ Sidebar  │              Main content area                    │
│          │                                                   │
├──────────┴──────────────────────────────────────────────────┤
│  ● mTLS OK  |  3 pending  |  Last event: 00:42 ago          │  ← status bar
└─────────────────────────────────────────────────────────────┘
```

- Top bar shows burn alerts prominently — one click opens the alert detail
- Status bar shows mTLS connection state (green = valid cert, red = cert error or expired)
- Lock button wipes in-memory session state and returns to the cert-auth screen

### 9.1 Dashboard

- Stat cards: Active Sessions, Burn Alerts, Pending Tasks, Uncleaned Artefacts, Credentials Harvested
- **Burn alert feed** — prominently displayed above other events; each alert shows which redirector, which sessions are affected, and recommended action
- Recent events feed with live WebSocket updates
- Infrastructure health panel: each redirector shown with check-in frequency sparkline

### 9.2 Sessions view

Full sessions table: Status | Session ID | Hostname | User | OS/Arch | IP | Transport | Last Seen | Tags

- Status: green (active), amber (stale), red (dead), **purple (suspect — canary/honeypot flag)**
- Transport indicator: shows which channel the session is using (HTTPS/DNS/SMB)
- Right-click context menu: Open Console, File Browser, Process Manager, Rotate Transport, Kill, Add Note, Flag as Suspect
- **Suspect flag**: when set, tasks are paused and the session is highlighted; operator must explicitly un-flag to resume tasking

### 9.3 Session Console

Tabbed per-session console with rendered output (tables for `proc_list`, thumbnails for `screenshot`, key-value grids for `sysinfo`, monospace for `shell`). Input bar with module selector and args. Task history with Ctrl+F search.

Adds OPSEC-specific features:
- **OPSEC rating per module**: each module is labelled Low / Medium / High risk before execution (e.g. `lsass_dump` is High, `sysinfo` is Low); operator sees the rating before clicking Run
- **Spawn-to selector**: per-task dropdown to choose the sacrificial process name
- **Fork-and-run toggle**: per-task choice between in-process and sacrificial process execution

### 9.4 Infrastructure view

Replaces the basic listeners view. Shows:
- All redirectors with status, check-in rate, last seen, and mTLS cert expiry countdown
- Burn status for each redirector (normal / suspected / confirmed)
- One-click burn action: revoke cert, remove from profile, destroy VPS
- Active domain list with categorisation status and age
- Fallback channel status per session

### 9.5 Artefacts and cleanup view

- Timeline of all artefacts created across all sessions in the current engagement
- Status per artefact: Pending cleanup / Cleaned / Ignored
- One-click "generate cleanup task" sends the appropriate removal module to the session
- Engagement close checklist: cannot mark engagement as closed with uncleaned artefacts unless explicitly overridden

### 9.6 All other views

- **File Browser**, **Process Manager**, **Payload Builder**, **Loot/Credentials**, **Screenshots**, **Network Graph**, **Operators**, **Audit Log**, **Settings** — same as previously planned, built after the security-critical views above
- **MITRE ATT&CK heatmap** — shows technique coverage; also flags techniques that are considered high-noise (easy to detect) vs low-noise
- **Engagement management** — scope enforcement, CIDR allowlists, out-of-scope warnings

---

## Phase 10 — Automation and Infrastructure

### 10.1 Ansible deployment

- Roles: `wraith-server`, `redirector`, `jumpbox` (WireGuard VPN termination)
- `deploy.yml`: full VPS provisioning — OS hardening, firewall, Docker, secrets, start server
- `rotate-redirector.yml`: spin up a new redirector, issue cert, update profile, destroy old one
- `teardown.yml`: full engagement teardown — revoke all certs, wipe secrets, destroy VPS

### 10.2 Payload builder API

- `POST /api/payloads` on the server: cross-compile implant for target OS/arch with chosen transport, profile, sleep interval, kill date, and sandbox checks
- Output stored encrypted in Postgres (same key as loot)
- SHA-256 and build metadata shown at download time; operator verifies before deploying

### 10.3 CI/CD pipeline

- GitHub Actions: `cargo test` on every PR; `cargo audit` on schedule; release workflow builds signed implant artifacts on tag push
- Implant artifacts for each release: Linux musl, Windows PE, Windows shellcode
- Build environment is hermetic (no internet access during compile) to prevent supply chain interference

### 10.4 Terraform infrastructure

- Terraform modules for: VPS (DigitalOcean, Linode, Vultr), DNS zone delegation, CDN front
- State stored locally (never in remote Terraform Cloud) with encryption at rest
- `make infra-plan` previews changes; `make infra-apply` executes; `make infra-destroy` tears down cleanly

---

## Ordering summary

```
Phase 1 (hardened foundation — mTLS, cert auth, server hardening)
    │
    ├──► Phase 2 (infrastructure OPSEC — redirectors, domains, burn detection)
    │         │
    │         └──► Phase 5 (traffic OPSEC — profiles, per-session crypto, transports)
    │
    ├──► Phase 3 (implant OPSEC — staging, anti-sandbox, sleep mask, callback hardening)
    │         │
    │         └──► Phase 6 (capabilities — modules, built on OPSEC foundation)
    │                   │
    │                   └──► Phase 7 (anti-forensics — artefact tracking, cleanup)
    │
    ├──► Phase 4 (operator security — cert lifecycle, network path, session isolation)
    │
    ├──► Phase 9 (GUI — built after server security is solid)
    │
    ├──► Phase 10 (automation — Ansible, Terraform, CI/CD)
    │
    └──► Phase 8 (evasion — last; only after everything above works cleanly)
```

**Rule:** At every phase, ask "what happens when this component is burned or compromised?"
If the answer is "the operator is exposed" or "other engagements are affected", the design is wrong.
Fix the isolation before moving on.
