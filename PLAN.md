# Wraith C2 — Implementation Plan

Phases are ordered by dependency and risk. Complete each phase before moving to the next.
Evasion is deliberately last — a stable, capable framework is more valuable than an evasive broken one.

---

## Phase 1 — Stabilise the Core

Get the existing code production-quality before adding anything new.

### 1.1 Configuration
- Move hardcoded defaults (`127.0.0.1:8080`, beacon interval, etc.) into a `config.toml` loaded at startup
- Server reads `DATABASE_URL` from env or config file; fail fast with a clear error if missing
- Add `--config` flag to server and client to point at a non-default config path

### 1.2 Error handling
- Replace all `unwrap()` / `expect()` calls with proper error propagation
- Return structured JSON error bodies from HTTP handlers (`{"error": "..."}`) instead of bare status codes
- Log every error at the server with a request ID for traceability

### 1.3 Operator token persistence
- Currently tokens live only in memory — a server restart logs everyone out
- Store session tokens in Postgres with an expiry timestamp
- Add a `DELETE /api/logout` endpoint that removes the token
- Enforce token expiry (e.g. 8 hours) on every authenticated request

### 1.4 Tests
- Unit tests for `dispatch()`, each common module, and password hashing
- Integration test that spins up the server against a test Postgres database and exercises login → task → result round-trip
- CI-friendly: `make test` runs everything with `cargo test`

### 1.5 Logging
- Structured JSON logging via `tracing` with fields: `request_id`, `session_id`, `operator`, `module`
- Log to stdout (easy to redirect to a file or forward later)
- Configurable log level via `RUST_LOG` env var

---

## Phase 2 — Server Capabilities

### 2.1 Multi-operator support
- Add `role` enforcement to gRPC: `admin` can manage operators, `operator` can task sessions, `viewer` is read-only
- `POST /api/operators` (admin only) — create operator accounts
- `DELETE /api/operators/:username` (admin only) — revoke access
- Per-session locking: an operator can claim a session so others cannot task it simultaneously

### 2.2 Listener management
- Replace the hardcoded HTTP listener with a dynamic listener registry stored in Postgres
- Operators can create/delete/enable/disable listeners from the client without restarting the server
- Each listener has: bind address, profile, redirector token, enabled flag
- Server spawns/kills `axum` listeners at runtime as they are created or deleted

### 2.3 Audit log
- Append-only `audit_log` table: `(id, timestamp, operator, action, target, detail)`
- Every operator action (login, logout, task, operator creation) writes a row
- gRPC endpoint `ListAuditLog` with pagination, exposed in the client

### 2.4 Real-time events
- Add a WebSocket endpoint `GET /ws/events` (operator-authenticated)
- Server pushes events: new session, session dropped, task completed
- Client subscribes on login and updates the UI without polling

### 2.5 Webhook notifications
- Config option: `webhook_url` + `webhook_events` (e.g. `["new_session", "task_complete"]`)
- Server POSTs a JSON payload to the URL on matching events
- Useful for alerting to Slack, Discord, or a custom dashboard

---

## Phase 3 — Operator Client (GUI)

The GUI is the operator's primary interface. The goal is a layout and feature set on par with
Cobalt Strike's split-pane console, Mythic's rich task rendering and search, and Sliver's
clean information density. Everything runs as a native egui desktop app.

---

### 3.0 Layout and chrome

**Overall structure** (never changes regardless of active view):

```
┌─────────────────────────────────────────────────────────────┐
│  [≡] WRAITH          Sessions: 4 active    operator: jakob  │  ← top bar
├──────────┬──────────────────────────────────────────────────┤
│          │                                                   │
│ Sidebar  │              Main content area                    │
│  nav     │         (changes with selected view)             │
│          │                                                   │
├──────────┴──────────────────────────────────────────────────┤
│  ● Connected  |  3 pending tasks  |  Last event: 00:42 ago  │  ← status bar
└─────────────────────────────────────────────────────────────┘
```

**Top bar**
- Wraith logo + version on the left
- Live count of active sessions (green dot) and stale sessions (amber dot) in the centre
- Logged-in operator name + role badge on the right
- Bell icon with a red badge for unread notifications; clicking opens the notification drawer
- Lock button to log out without closing the window

**Sidebar navigation** (icon + label, collapsible to icon-only)
- Dashboard
- Sessions
- Listeners
- Payload Builder
- Loot & Credentials
- Screenshots
- Network Graph
- Operators *(admin only)*
- Audit Log
- Settings

**Status bar**
- Server connection indicator (green/red dot + address)
- Count of pending tasks across all sessions
- Timestamp of the most recent event
- Clickable: opens the event feed drawer

**Notification system**
- Toast popups in the bottom-right corner for: new session check-in, task completed, session dropped
- Each toast shows session hostname, event type, and timestamp
- Toasts are dismissible; they also auto-expire after 8 seconds
- All notifications accumulate in the notification drawer until cleared

---

### 3.1 Dashboard view

Inspired by Mythic's overview page — gives an at-a-glance picture of the engagement.

- **Stat cards** across the top: Active Sessions, Total Sessions, Tasks Today, Credentials Harvested, Files Collected
- **Recent events feed** — last 20 events (new session, task completed, operator login) with timestamps; auto-refreshes via WebSocket
- **Session health chart** — simple bar or sparkline showing check-in frequency over the last hour per active session
- **Top active sessions** — table of the 5 most recently active sessions with hostname, user, OS, last seen
- **Quick-task bar** — select any active session from a dropdown and dispatch a module without navigating away

---

### 3.2 Sessions view

The primary working view. Inspired by Cobalt Strike's beacon list and Mythic's callbacks table.

**Sessions table columns:**
`Status | Session ID (short) | Hostname | User | OS / Arch | IP | Profile | Last Seen | Tags | Actions`

- **Status indicator**: filled green circle = active (checked in within 2 min), amber = stale (2–10 min), red = dead (>10 min)
- **Sortable columns**: click any header to sort ascending/descending
- **Search/filter bar**: free-text search across hostname, user, IP, tags; OS filter dropdown; status filter toggle
- **Tags**: inline chips on each row; click to add/remove tags; tags are stored server-side and shared across operators
- **Notes tooltip**: hover the session ID to see operator notes for that session
- **Row actions (right-click context menu)**:
  - Open Console
  - Open File Browser
  - Open Process Manager
  - Inject shellcode…
  - Kill session
  - Add note…
  - Add/remove tag…
  - Copy session ID
- **Multi-select**: hold Shift or Ctrl to select multiple rows; right-click menu shows bulk actions (kill, tag, task all)
- **Double-click** a row to open the Session Console for that session

---

### 3.3 Session Console

The main tasking interface. Each session opens its own console in a tab, inspired by Cobalt Strike's beacon console.

**Layout:**

```
┌─ Sessions ──────────────────────────────────────────────────────┐
│  [WIN-DC01 \ SYSTEM]  [LINUXWEB01 \ www-data]  [+]             │  ← tab bar
├─────────────────────────────────────────────────────────────────┤
│  Hostname: WIN-DC01   User: SYSTEM   OS: Windows 10 x64        │
│  IP: 10.10.10.5       Profile: default    Last seen: 00:12 ago │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [00:01:04]  operator  →  shell whoami                         │
│  [00:01:05]  ✓          nt authority\system                    │
│                                                                  │
│  [00:03:12]  operator  →  proc_list                            │
│  [00:03:13]  ✓         ┌──────────┬──────┬───────────┐        │
│                         │ PID      │ Name │ User      │        │
│                         │ 4        │ Sys  │ SYSTEM    │        │
│                         │ 688      │ lsas │ SYSTEM    │        │
│                         │ ...      │ ...  │ ...       │        │
│                         └──────────┴──────┴───────────┘        │
│                                                                  │
│  [00:05:44]  operator  →  screenshot                           │
│  [00:05:45]  ✓         [image thumbnail — click to enlarge]    │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│  Module: [shell          ▾]  Args: [____________]  [Run ▶]     │
│  Templates: [initial-recon ▾]  [Run template]                  │
└─────────────────────────────────────────────────────────────────┘
```

- **Tab bar**: one tab per open session; tabs show hostname + username; middle-click to close
- **Session metadata strip**: key fields shown above the task history, always visible
- **Task history**: scrollable log of all tasks for this session, oldest at top
  - Each entry: timestamp, operator name (colour-coded per operator), module + args, then rendered output below
  - Status icons: ⏳ pending, ✉ sent, ✓ completed (green), ✗ failed (red)
  - **Rendered output by module type**:
    - `proc_list` → sortable table (PID, name, user, memory)
    - `sysinfo` → key-value grid
    - `screenshot` → inline thumbnail, click to open full-size in an overlay
    - `file_get` / `file_put` → file name + size, download button
    - `shell` → monospace pre block with syntax highlighting for common CLIs
    - Everything else → pretty-printed JSON with collapsible nested objects
- **Input bar**: module selector dropdown + args text field + Run button
- **Template runner**: select a saved template, runs all tasks sequentially with a progress indicator
- **History search**: Ctrl+F opens a search bar that highlights matching text in the task history
- **Copy button** on every output block

---

### 3.4 Interactive Shell

A dedicated PTY-backed terminal within a session console tab, inspired by Sliver's interactive sessions.

- Separate tab labelled `[shell]` within the session console tab
- Full terminal emulator widget (VT100/ANSI escape codes, colours, cursor movement)
- Input is sent to the implant as raw stdin; output is streamed back and rendered character by character
- Arrow key history, Ctrl+C, Ctrl+D handled correctly
- Shell is kept alive between operator interactions — reconnecting to the same session reopens the existing shell if the implant is still running it
- Resize events are forwarded to the PTY so ncurses tools render correctly

---

### 3.5 File Browser

Inspired by Cobalt Strike's file browser and Mythic's file management view.

```
┌─ File Browser: WIN-DC01 ─────────────────────────────────────────┐
│  Path: [C:\Users\Administrator\          ] [Go] [↑ Up] [Refresh] │
├──────────────────┬───────────┬─────────────┬──────────────────────┤
│ Name             │ Size      │ Modified    │ Actions              │
│ 📁 Desktop       │ —         │ 2024-01-05  │                      │
│ 📁 Documents     │ —         │ 2024-01-03  │                      │
│ 📄 passwords.txt │ 1.2 KB    │ 2024-01-06  │ [Download] [Delete]  │
│ 📄 notes.docx    │ 48.3 KB   │ 2023-12-01  │ [Download] [Delete]  │
├──────────────────┴───────────┴─────────────┴──────────────────────┤
│ [Upload file…]                                  [New folder]       │
└───────────────────────────────────────────────────────────────────┘
```

- Path bar: editable, with breadcrumb navigation above the table
- Double-click a folder to navigate into it
- Download: fetches the file via `file_get`, saves to the operator's local machine
- Upload: opens a native file picker; sends via `file_put`; progress bar during transfer
- Downloaded files are saved to `~/wraith-loot/<session-id>/` by default, configurable in settings
- Right-click on any file: Download, Delete, Add to Loot

---

### 3.6 Process Manager

Inspired by Cobalt Strike's process list with inject actions.

- Table: PID, PPID, Name, User, Architecture, Memory (MB)
- Colour coding: SYSTEM/root processes in red, current implant process highlighted in amber
- Search bar to filter by name or user
- Right-click actions:
  - Kill process
  - Inject into process *(Windows only — opens shellcode input dialog)*
  - Migrate implant to this process *(future)*
- Refresh button re-dispatches `proc_list`; auto-refresh toggle (every 30s)

---

### 3.7 Listeners view

Manage C2 listeners without restarting the server (requires Phase 2.2).

- Table: Name, Protocol, Bind address, Profile, Redirector token (masked), Status, Sessions
- **Create listener** button: opens a form with fields for all listener parameters
- Toggle switch on each row to enable/disable a listener
- Delete button (confirms before removing)
- Status badge: green = listening, red = error (hover to see error message)

---

### 3.8 Payload Builder

Wizard-style flow inspired by Mythic's payload creation and Cobalt Strike's payload generator.

**Step 1 — Target**
- OS: Linux / Windows / macOS
- Architecture: x86_64 / x86 / aarch64
- Format: ELF binary / PE executable / shellcode / DLL

**Step 2 — C2 configuration**
- Listener: dropdown of active listeners
- Sleep interval + jitter percentage
- Max retries before implant exits

**Step 3 — Options**
- Profile name (for traffic shaping)
- Kill date: implant exits after this date
- Working directory for execution

**Step 4 — Review and build**
- Summary of all selected options
- Build button triggers `POST /api/payloads` on the server
- Progress indicator while the server cross-compiles
- Download button appears when the build completes
- SHA-256 hash of the output file displayed for verification

Built payloads are listed in a history table below the wizard with download and re-download links.

---

### 3.9 Loot and Credentials view

Inspired by Mythic's credentials tab and Cobalt Strike's credentials store.

**Credentials table columns:**
`Type | Value | Source host | Module | Captured at | Actions`

- Types: `hash (NTLM)`, `hash (bcrypt)`, `cleartext`, `Kerberos ticket`, `SSH key`, `cookie`, `API token`
- Search/filter by type, hostname, or keyword
- Export to CSV button
- Right-click → Copy value, Mark as used, Delete
- `hash` entries have a Crack button that prepares a hashcat command for the operator to run locally

**Files table** (separate tab within the loot view):
- All files collected via `file_get` or downloaded through the file browser
- Columns: filename, source path, source session, size, timestamp
- Download again, open in system viewer, delete

---

### 3.10 Screenshots gallery

- Grid of thumbnail images, newest first
- Each thumbnail labelled with hostname and timestamp
- Click to open full-size in an overlay
- Download button on each image
- Filter by session or date range

---

### 3.11 Network Graph view

Visual topology map inspired by Cobalt Strike's pivot graph and Mythic's callback graph.

- Each session is a node: icon reflects OS (penguin for Linux, window for Windows)
- Node colour reflects status: green/amber/red matching the sessions table
- Edges show the communication path: implant → redirector → server, or implant → peer (SMB pivot) → server
- Click a node to open a detail panel (same metadata as the session console header)
- Double-click a node to open the session console for that session
- Drag nodes to rearrange; layout auto-organises on first load
- Zoom and pan with mouse wheel and middle-drag

---

### 3.12 Operators view *(admin only)*

- Table: username, role, last login, active sessions claimed
- Create operator: form with username + role selector; generated password shown once
- Reset password button
- Delete operator (cannot delete self)
- Role badges: `admin` in red, `operator` in blue, `viewer` in grey

---

### 3.13 Audit Log view

- Paginated table: timestamp, operator, action, target, detail
- Filter by operator, action type, or date range
- Export to CSV
- Auto-scrolls to the newest entry when the log view is open

---

### 3.14 Settings view

- **Server**: server URL, gRPC URL, connection timeout
- **Appearance**: accent colour picker, font size, sidebar collapsed by default toggle
- **Notifications**: toggle per event type (new session, task complete, session dropped)
- **Loot directory**: where downloaded files are saved
- **Keyboard shortcuts**: reference table (not configurable yet, just displayed)
- **About**: version, build date, license

---

### 3.15 Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+1` … `Ctrl+9` | Switch to sidebar view by position |
| `Ctrl+T` | Open new session console tab |
| `Ctrl+W` | Close current session console tab |
| `Ctrl+Tab` | Next session console tab |
| `Ctrl+Shift+Tab` | Previous session console tab |
| `Ctrl+F` | Search within current view |
| `Ctrl+R` | Refresh current view |
| `Ctrl+L` | Lock (log out) |
| `Escape` | Close overlay / dismiss notification |

---

## Phase 4 — Implant Modules

Build modules in this order: information gathering → file operations → lateral movement → privilege escalation.

### 4.1 Information gathering
- `screenshot` — capture the screen (BitBlt on Windows, X11/Wayland on Linux), return as base64 PNG
- `clipboard` — read current clipboard contents
- `browser_dump` — extract Chrome/Firefox saved passwords and cookies from profile directories
- `env` — dump all environment variables

### 4.2 Process and execution
- `proc_kill` — kill a process by PID
- `proc_inject` (Windows) — inject shellcode into a remote process via `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
- `execute_assembly` (Windows) — load and run a .NET assembly from memory using the CLR hosting API

### 4.3 Persistence
- **Windows**: registry Run key, scheduled task (XML via `schtasks`), startup folder LNK
- **Linux**: crontab entry, systemd user unit (`~/.config/systemd/user/`), `.bashrc` append
- Each persist module takes an `--action install|remove` argument

### 4.4 Privilege escalation (Linux)
- `sudo_enum` — run `sudo -l` and parse exploitable rules
- `suid_scan` — find SUID binaries and cross-reference against a known-exploit list embedded in the binary
- `cap_scan` — list files with dangerous capabilities (`cap_setuid`, `cap_net_raw`)

### 4.5 Privilege escalation (Windows)
- `token_list` — enumerate tokens of running processes using `OpenProcessToken`
- `token_steal` — impersonate a higher-privileged token
- `uac_bypass` — attempt known UAC bypass techniques (fodhelper, eventvwr)

### 4.6 Lateral movement
- `port_scan` — TCP connect scan of a CIDR range, returns open ports
- `smb_exec` — execute a command on a remote host via SMB (`net use` + service creation)
- `wmi_exec` — execute a command on a remote host via WMI (`Win32_Process.Create`)
- `ssh_exec` — execute a command on a remote host using harvested SSH credentials

### 4.7 Tunnelling
- `socks5` — start a SOCKS5 proxy server on the implant; operator connects through it via a local port forward
- `port_fwd` — forward a specific remote port to the operator's machine

---

## Phase 5 — Transport Channels

### 5.1 WebSocket transport
- Replace HTTP polling with a persistent WebSocket connection
- Operator-configurable: `transport = "ws"` or `transport = "http"` in the implant config
- Reduces latency to near-zero; bidirectional command push

### 5.2 DNS C2
- Implant encodes data as DNS TXT queries to an operator-controlled domain
- Server acts as an authoritative DNS resolver for that domain
- Slow but highly evasive; suitable for heavily firewalled networks
- Requires a VPS with control over a DNS zone

### 5.3 SMB named-pipe transport
- Implants on internal hosts relay traffic through a single internet-facing implant via SMB named pipes
- Enables C2 on hosts with no direct internet access
- Requires a `--relay` mode on the implant that acts as a peer-to-peer proxy

### 5.4 ICMP transport
- Encode data in ICMP echo request/reply payloads
- Needs raw socket access (root / CAP_NET_RAW on Linux, admin on Windows)
- Use as a fallback channel when all TCP/UDP ports are blocked

### 5.5 Domain fronting
- Route HTTPS traffic through a CDN (Cloudflare, Azure Front Door) to hide the true server IP
- Implant sends `Host: <legit-domain>` header; CDN forwards to the actual server
- Configured via the redirector profile: `fronted_host = "legitimate.cdn-domain.com"`

---

## Phase 6 — Automation and Infrastructure

### 6.1 Payload builder
- Server-side API endpoint `POST /api/payloads` that triggers a cross-compile
- Parameters: target OS, arch, server URL, sleep interval, profile name, format (ELF/PE/shellcode)
- Output stored as a blob in Postgres, downloadable from the client
- Requires the server host to have the cross-compile toolchains installed

### 6.2 Ansible deployment
- `ansible/` directory with roles: `postgres`, `wraith-server`, `redirector`
- Single playbook `deploy.yml` that provisions a fresh VPS (Ubuntu/Debian) end-to-end:
  - Installs Postgres, creates database and user
  - Copies the server binary, creates a systemd unit, starts it
  - Provisions the admin account and prints the password
- Inventory file with variables: `server_host`, `redirector_hosts`, `domain`

### 6.3 Redirector auto-provisioning
- CLI subcommand `wraith-server provision-redirector --host <ip> --token <secret>`
- Uses the Ansible redirector role under the hood via `ansible-playbook` subprocess call
- Registers the new redirector in the database so operators can see it in the client

### 6.4 TLS automation
- Integrate `instant-acme` (Rust ACME client) into the redirector
- On first start, redirector requests a Let's Encrypt certificate for its domain
- Certificates are renewed automatically before expiry
- Server ↔ redirector communication uses mTLS with a shared CA generated at deploy time

### 6.5 CI/CD pipeline
- GitHub Actions workflow `.github/workflows/release.yml`:
  - On tag push: build Linux musl and Windows PE implants
  - Upload artifacts to the GitHub release
  - Run `cargo test` on every PR
- Separate workflow for `cargo audit` to catch vulnerable dependencies

---

## Phase 7 — Evasion

Only implement after the framework is stable, tested, and operationally useful.
Evasion without a reliable foundation creates bugs that are hard to distinguish from detection.

### 7.1 In-memory execution
- Remove implant from disk after first execution (overwrite then delete self on Linux; `MoveFileEx` `MOVEFILE_DELAY_UNTIL_REBOOT` on Windows)
- Reflective loader: implant can load a second-stage PE from memory without calling `LoadLibrary`

### 7.2 Sleep evasion
- **Ekko / Foliage pattern**: encrypt implant's own memory (RW) while sleeping, decrypt on wake
- Implemented as a custom sleep function that:
  1. Queues an APC to encrypt the heap
  2. Sleeps via `NtWaitForSingleObject` with jitter
  3. Queues an APC to decrypt before resuming
- Defeats memory scanners that run while the implant is idle

### 7.3 API unhooking
- On startup, overwrite the `.text` section of `ntdll.dll` in the current process with a clean copy read from `\KnownDlls\ntdll.dll` (bypasses userland AV hooks)
- Alternatively: map a fresh copy of `ntdll.dll` from disk before any hooked function is called

### 7.4 Direct syscalls
- Generate syscall stubs at runtime (Syswhisper3 / HellsGate pattern): walk the export table to find SSNs, emit a small `syscall` stub per function
- Replace all `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` calls with direct stubs
- Eliminates dependence on userland `ntdll.dll` entirely for core operations

### 7.5 Stack spoofing
- Before making any suspicious API call, walk back up the stack and replace return addresses with addresses inside legitimate modules
- Defeats EDR stack-walk detectors that flag calls originating from unbacked memory

### 7.6 AMSI / ETW bypass
- Patch `AmsiScanBuffer` in the current process to always return `AMSI_RESULT_CLEAN`
- Zero out the first bytes of `EtwEventWrite` to suppress ETW telemetry
- Both patches applied in-memory only; no disk writes

### 7.7 Process injection improvements
- Replace `CreateRemoteThread` with `NtQueueApcThread` (early-bird) or `RtlCreateUserThread`
- PPID spoofing: create sacrificial processes with a spoofed parent (e.g. `explorer.exe`) using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
- Stomping: write shellcode into an existing RX section of a legitimate module rather than allocating new RWX memory

### 7.8 PE obfuscation
- String encryption: XOR-encrypt all hardcoded strings (URLs, module names) at compile time; decrypt at runtime
- Import obfuscation: resolve WinAPI functions by hash at runtime instead of using the import table
- Section name randomisation and fake rich header to defeat static PE signatures

### 7.9 Traffic obfuscation
- Malleable HTTP profiles: randomise URI paths, headers, user-agent, and body padding per request
- Encrypt C2 traffic with a per-session AES-256-GCM key negotiated at first check-in (independent of TLS)
- Jitter: randomise sleep interval within a configurable range to avoid beacon timing signatures

---

## Phase 8 — Active Directory Attacks

Active Directory is the primary target in most enterprise engagements. These modules require a foothold on a domain-joined host with at least a low-privileged domain user.

### 8.1 Enumeration
- `ad_info` — dump domain name, DC hostnames, domain functional level, and forest trust relationships via LDAP
- `ad_users` — enumerate all domain user accounts: SAMAccountName, UPN, last logon, password last set, account flags (disabled, never expires, etc.)
- `ad_groups` — list all groups and their members; flag high-value groups (Domain Admins, Enterprise Admins, Schema Admins, Account Operators)
- `ad_computers` — list domain-joined computers with OS version and last logon
- `ad_spns` — find accounts with SPNs set (Kerberoasting targets); output ready for hashcat
- `ad_asrep` — find accounts with `DONT_REQUIRE_PREAUTH` set (AS-REP roasting targets)
- `ad_gpo` — list all Group Policy Objects and which OUs they apply to; flag GPOs with write access for the current user
- `ad_acl` — enumerate ACLs on high-value objects (Domain object, AdminSDHolder, GPOs) and flag abusable rights (GenericAll, WriteDACL, GenericWrite, ForceChangePassword)
- `ad_trusts` — enumerate inter-domain and inter-forest trusts with direction and transitivity

### 8.2 Credential attacks
- `kerberoast` — request TGS tickets for all SPN accounts and return the encrypted tickets for offline cracking with hashcat (`-m 13100`)
- `asrep_roast` — request AS-REP for accounts without pre-authentication and return hashes for offline cracking (`-m 18200`)
- `pass_the_hash` — authenticate to remote services using an NTLM hash without knowing the cleartext password (via `NtLmSsp`)
- `pass_the_ticket` — inject a Kerberos ticket (`.kirbi`) into the current session using `LsaCallAuthenticationPackage`
- `overpass_the_hash` — use an NTLM hash to request a full Kerberos TGT, converting it to a usable ticket
- `golden_ticket` — forge a TGT using the KRBTGT hash (requires Domain Admin / DCSync); provides persistent domain access
- `silver_ticket` — forge a TGS for a specific service using the service account hash; bypasses the KDC entirely

### 8.3 Privilege escalation
- `dcsync` — impersonate a domain controller and request password hashes for any account using `MS-DRSR` (`DsGetNCChanges`); returns NTLM and AES Kerberos keys
- `ntds_dump` — dump `NTDS.dit` and `SYSTEM` hive from a DC (volume shadow copy technique) for offline extraction
- `lsass_dump` — dump LSASS process memory via `MiniDumpWriteDump` or direct syscall alternative; pipe output to `pypykatz` / `mimikatz`
- `sam_dump` — dump SAM database and SYSTEM hive for local account hashes using VSS or registry save

### 8.4 Lateral movement
- `bloodhound_collect` — run a BloodHound-compatible JSON collection (sessions, ACLs, group memberships, trusts) and return the ZIP for import into BloodHound
- `psremote` — execute a command on a remote host via PowerShell Remoting (WinRM); supports both NTLM and Kerberos auth
- `rdp_hijack` — hijack a disconnected RDP session using `tscon` without knowing the user's password (requires SYSTEM)
- `dcom_exec` — execute a command on a remote host via DCOM (`MMC20.Application`, `ShellBrowserWindow`) to avoid creating a new service

---

## Phase 9 — macOS Support

macOS is common in corporate environments, particularly at developer and executive endpoints.

### 9.1 Core platform support
- Add `#[cfg(target_os = "macos")]` module tree mirroring the Linux structure
- Implement platform-specific `sysinfo` fields: macOS version, hardware model, SIP status
- Handle macOS code signing requirements for running unsigned binaries

### 9.2 Credential harvesting
- `keychain_dump` — extract credentials from the user's login keychain using the Security framework (`SecItemCopyMatching`); returns Wi-Fi passwords, stored web credentials, SSH passphrases
- `safari_dump` — extract Safari saved passwords from `~/Library/Safari/` (requires Full Disk Access or keychain access)
- `macos_browser_dump` — extract Chrome/Firefox/Brave credentials from their macOS profile paths

### 9.3 Privilege escalation
- `tcc_bypass` — enumerate apps with TCC permissions (Full Disk Access, Camera, Microphone) that can be abused to inherit permissions; document known bypass techniques per macOS version
- `sudo_creds` — monitor for `sudo` invocations and capture the password via a TTY hook
- `launch_agent_persist` — install or remove persistence via a `LaunchAgent` plist in `~/Library/LaunchAgents/`
- `launch_daemon_persist` — install or remove persistence via a `LaunchDaemon` plist (requires root); survives reboots as a system service

### 9.4 Evasion (macOS-specific)
- **Gatekeeper bypass** — bundle the implant in a way that passes Gatekeeper checks on first execution
- **Notarisation awareness** — detect if Gatekeeper or XProtect is active and adapt execution accordingly
- **Dylib hijacking** — identify applications that load a missing dylib and plant a malicious one in the search path
- **AppleScript automation** — use `osascript` to perform UI actions (keystrokes, clicks) that bypass permission prompts

---

## Phase 10 — Cloud and Container Post-Exploitation

Engagements increasingly involve cloud-native infrastructure. These modules run on hosts inside cloud environments.

### 10.1 Cloud metadata and credentials
- `aws_meta` — query the AWS Instance Metadata Service (IMDS v1/v2) at `169.254.169.254` for IAM role credentials, instance identity, user-data, and security groups
- `gcp_meta` — query the GCP metadata server for service account tokens, project ID, and startup scripts
- `azure_meta` — query the Azure IMDS for managed identity tokens, subscription ID, and VM metadata
- `aws_enum` — use harvested IAM credentials to enumerate S3 buckets, EC2 instances, Lambda functions, IAM users, and role policies via the AWS API
- `az_enum` — use a stolen Azure token to enumerate subscriptions, resource groups, storage accounts, and Key Vault secrets

### 10.2 Container escape
- `docker_escape` — detect if running inside a Docker container (`.dockerenv`, cgroup checks) and attempt escape techniques: privileged container host mount, `runc` CVEs, `docker.sock` abuse
- `k8s_escape` — detect Kubernetes environment variables and attempt to access the API server using the pod's service account token; enumerate pods, secrets, and config maps across namespaces
- `cgroup_escape` — exploit a writable `release_agent` in a cgroup v1 hierarchy (requires `SYS_ADMIN` or privileged container) to execute on the host

### 10.3 Kubernetes lateral movement
- `k8s_secret_dump` — list and decode all secrets in accessible namespaces; flag secrets containing AWS keys, database URLs, or API tokens
- `k8s_exec` — exec into another pod using the Kubernetes API (`/exec` endpoint) — lateral movement without network connections
- `k8s_create_pod` — create a privileged pod that mounts the host filesystem for persistent access or node escape
- `k8s_rbac_enum` — enumerate RBAC roles and bindings to find over-privileged service accounts or wildcard permissions

### 10.4 Serverless and CI/CD
- `env_scan` — scan environment variables for secrets: AWS keys (`AKIA`), GitHub tokens (`ghp_`), database URLs, private keys — common in Lambda, Cloud Run, GitHub Actions runners
- `cicd_detect` — detect if running inside a CI/CD runner (GitHub Actions, GitLab CI, CircleCI, Jenkins) and extract the runner token, repository secrets, and pipeline permissions

---

## Phase 11 — Extension and Plugin System

An extension system allows new modules to be loaded at runtime without recompiling the implant, similar to Cobalt Strike's Aggressor scripts and Sliver's Armory.

### 11.1 BOF (Beacon Object File) loader
- Implement a COFF/BOF loader in the implant: parse the COFF header, relocate sections, resolve API imports, and execute the entry point in-process
- BOFs run in the implant's process without spawning a new process — stealthier than `shell`
- Operator sends the BOF binary as a base64 task argument; output is captured and returned
- Compatible with the Cobalt Strike BOF ecosystem (hundreds of public BOFs work without modification)

### 11.2 Reflective DLL loading
- Implement a reflective DLL loader: map a PE image from memory (fix relocations, resolve imports, call `DllMain`)
- Operator sends the DLL as a base64 argument with an optional export function name to call
- Enables running tools like `Rubeus`, `SharpHound`, `Seatbelt` entirely in-memory

### 11.3 In-memory .NET (execute-assembly)
- Host the CLR inside the implant process using `ICLRRuntimeHost`
- Load a .NET assembly from a byte array without writing to disk
- Capture stdout/stderr by redirecting the assembly's console output
- Enables running `SharpHound`, `Certify`, `Rubeus`, `SharpDPAPI` directly

### 11.4 Server-side extension API
- Define a `wraith-ext` Rust trait crate that third-party modules implement
- Extensions compile to shared libraries (`.so` / `.dll`) loaded by the server at startup from an `extensions/` directory
- Each extension can register new gRPC endpoints, HTTP routes, and custom GUI views via a registration API
- Provides hooks: `on_session_new`, `on_task_complete`, `on_checkin`

### 11.5 Armory (extension marketplace)
- `armory.toml` index file listing available extensions with name, version, description, and download URL
- `wraith-server armory list` — show available extensions
- `wraith-server armory install <name>` — download, verify SHA-256, and install extension
- GUI: Armory view in the client showing installed and available extensions with install/remove buttons

---

## Phase 12 — Anti-Forensics and OPSEC

Reduce the forensic footprint of the operation after tasks complete.

### 12.1 Artefact cleanup
- `timestomp` — modify file `Created`, `Modified`, and `Accessed` timestamps to match a reference file using `SetFileTime` (Windows) or `utimensat` (Linux)
- `log_clear` — clear Windows Event Log channels (Security, System, Application, PowerShell) using `EvtClearLog`; on Linux, truncate `/var/log/auth.log`, `/var/log/syslog`, and `~/.bash_history`
- `prefetch_delete` — delete Windows prefetch files for executed binaries from `C:\Windows\Prefetch\`
- `mft_stomp` — overwrite the `$STANDARD_INFORMATION` timestamps in the NTFS MFT entry to match `$FILE_NAME` (defeats common timestomping detection)

### 12.2 Anti-memory-forensics
- `heap_wipe` — overwrite sensitive strings (URLs, passwords, keys) in the implant's heap before sleeping or executing sensitive operations
- `stack_wipe` — zero stack frames of sensitive functions before returning
- `pe_header_stomp` — zero out the DOS/PE header of the loaded implant image in memory to defeat `pe-sieve` and `Get-InjectedThread` type tools

### 12.3 Network OPSEC
- `conn_hide` — on Linux, use `LD_PRELOAD` or `ebpf` to hide the C2 TCP connection from `netstat` / `ss`
- `dns_flush` — flush the DNS cache (`ipconfig /flushdns` on Windows, `systemd-resolve --flush-caches` on Linux) after DNS C2 sessions
- **Canary detection** — before executing sensitive operations, check for sandbox/VM indicators: CPUID hypervisor bit, low uptime, small disk, user interaction metrics; sleep and retry if detected

### 12.4 Process OPSEC
- **Spawn-to** — all post-exploitation tasks that need a new process should spawn into a configurable "spawn-to" process (e.g. `svchost.exe`, `RuntimeBroker.exe`) rather than `cmd.exe` or `powershell.exe`
- **Fork-and-run vs in-process toggle** — operator can choose per-task whether to run in a sacrificial process (safer, isolated) or in-process (stealthier, no new process)
- **Module cleanup** — after reflective DLL or BOF execution, unmap the allocation and zero the memory

---

## Phase 13 — Reporting and Engagement Management

Tie post-exploitation activity to deliverables and documentation.

### 13.1 Engagement management
- Add an `engagements` table in Postgres: `(id, name, client, start_date, end_date, scope_cidrs, notes)`
- Sessions are tagged to an engagement; all loot, tasks, and audit log entries are scoped per engagement
- Operators can switch between engagements without logging out
- GUI: Engagement selector in the top bar; create/archive engagements from the Settings view

### 13.2 MITRE ATT&CK mapping
- Each module is annotated with its ATT&CK technique IDs (e.g. `shell` → T1059.004, `kerberoast` → T1558.003)
- GUI: ATT&CK Navigator-style heatmap view showing which techniques have been exercised in the current engagement
- Export the heatmap as a JSON layer file importable into the official ATT&CK Navigator

### 13.3 Artefact tracking
- Every file dropped, process created, registry key written, and network connection made by a module is logged to an `artefacts` table
- GUI: Artefacts view showing a timeline of all side effects with session, module, and timestamp
- Operator can mark artefacts as cleaned up; uncleaned artefacts are highlighted before engagement close

### 13.4 Automated report generation
- `wraith-server generate-report --engagement <id> --format [html|pdf|md]`
- Report includes: engagement metadata, timeline of events, sessions discovered, credentials harvested, techniques used (with ATT&CK IDs), artefacts left behind, and recommendations
- HTML/PDF output uses a template that can be customised per client
- GUI: Generate Report button in the engagement view with format selector and download link

### 13.5 Screenshot and evidence tagging
- Operators can annotate screenshots and task outputs with a caption and evidence tag (e.g. `domain-admin-achieved`, `data-exfil`, `persistence-established`)
- Tagged evidence is automatically included in the relevant report section
- GUI: Right-click on any output block → "Add to report evidence" → enter caption

### 13.6 Scope enforcement
- Import a scope definition (CIDR ranges, hostnames, out-of-scope IPs) per engagement
- Server warns (or blocks, configurable) if a module targets a host outside the defined scope
- `port_scan`, `smb_exec`, `wmi_exec`, `ssh_exec` all check scope before executing
- Scope violations are logged to the audit log regardless of whether they were blocked

---

## Rough ordering summary

```
Phase 1 (core stability)
    │
    ├──► Phase 2 (server)  ──────────────────────────────────────────────────────┐
    │        │                                                                    │
    │        └──► Phase 3 (GUI)                                                  │
    │                 │                                                           │
    │    Phases 2+3 unlock:                                                      │
    │                 │                                                           ▼
    └────────────────►├──► Phase 4 (implant modules)
                      │         │
                      │         ├──► Phase 8  (Active Directory)
                      │         ├──► Phase 9  (macOS)
                      │         └──► Phase 10 (cloud + containers)
                      │
                      ├──► Phase 5 (transports)
                      │
                      ├──► Phase 6 (automation + infra)
                      │         │
                      │         └──► Phase 11 (extension system)
                      │
                      ├──► Phase 12 (anti-forensics + OPSEC)
                      │
                      ├──► Phase 13 (reporting + engagement mgmt)
                      │
                      └──► Phase 7  (evasion)  ← last, always
```

**Phase 1** must be complete before anything else — an unstable foundation makes all later work harder.

**Phases 2 and 3** can be worked in parallel: server features (listeners, RBAC, real-time events) unlock
corresponding GUI views. Build server-side capability first, then wire it into the GUI.

**Phase 3 implementation order** within the GUI:
1. Layout chrome (top bar, sidebar, status bar, notifications) — everything hangs off this
2. Sessions view + Session Console (core tasking loop)
3. File Browser + Process Manager (most used after console)
4. Dashboard (needs real-time events from Phase 2.4)
5. Listeners + Payload Builder (needs Phase 2.2 and Phase 6.1)
6. Loot, Screenshots, Network Graph, Operators, Audit Log (add as backend support lands)
7. ATT&CK heatmap + Artefacts + Report generation (needs Phase 13)

**Phases 8, 9, 10** are implant module expansions — they can be built in parallel with each other
once Phase 4 is underway. Each is self-contained: new files in the appropriate `modules/` directory.

**Phase 11** (extension system) requires a stable server and implant API — do not start until
Phases 2 and 4 are solid, since the extension API surface will change frequently before that.

**Phase 12** (anti-forensics) shares implementation patterns with Phase 7 (evasion) — work them
together once evasion groundwork is laid.

**Phase 13** (reporting) can start as soon as Phase 2 (server/database) is done — it only needs
the existing data model and doesn't depend on any implant capabilities.

**Phase 7** evasion is last. Do not start until the framework passes real operational use without
evasion — bugs in an unevaded implant are much easier to diagnose than bugs in an evaded one.
