# Wraith C2 — Future Features

Pick from this list when extending the framework. Items are grouped by area; complexity notes are rough guidance.

---

## Implant Capabilities

### Execution
- **BOF (Beacon Object File)** — load and execute COFF objects in-process without spawning a new process
- **Reflective DLL injection** — load a DLL from memory without touching disk
- **In-memory .NET execution** — host CLR and execute managed assemblies
- **Shellcode injection** — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (classic)
- **Process hollowing** — spawn suspended process, swap image, resume
- **Early-bird APC injection** — queue shellcode via NtQueueApcThread before the thread starts
- **PPID spoofing** — create processes with an arbitrary parent PID to fool process trees
- **Sacrificial process** — execute risky tasks in a disposable child, kill it on completion

### Post-exploitation modules
- **screenshot** — BitBlt / CGDisplayCreateImage capture, send back as base64
- **keylogger** — SetWindowsHookEx / evdev reader, buffered upload
- **clipboard** — read/write system clipboard
- **browser-dump** — extract saved passwords/cookies from Chrome/Firefox profile
- **lsass-dump** — MiniDumpWriteDump or direct syscall alternative
- **token theft** — OpenProcessToken, ImpersonateLoggedOnUser, make-token (LogonUser)
- **DPAPI decrypt** — decrypt Chrome master key, credential blobs
- **port-forward** — bind/connect TCP tunnel through the implant
- **SOCKS5 proxy** — full SOCKS5 server inside the implant using tokio channels
- **file-browser** — recursive directory listing with metadata
- **registry** — read/write/delete Windows registry keys
- **service-control** — start/stop/create Windows services
- **wmi-exec** — lateral movement via WMI (Win32_Process.Create)
- **dcom-exec** — lateral movement via DCOM (MMC20.Application, ShellBrowserWindow)
- **ssh-exec** — lateral movement using harvested SSH credentials

### Evasion
- **Sleep mask / Ekko / Foliage** — encrypt implant heap while sleeping, evade memory scans
- **Stack spoofing** — fake the call stack during API calls to defeat stack-walk detectors
- **Direct syscalls / Syswhisper** — bypass userland hooks by calling syscalls directly
- **AMSI patching** — patch AmsiScanBuffer in-process to blind AV script scanning
- **ETW patching** — zero out EtwEventWrite to suppress telemetry
- **Unhooking** — overwrite ntdll.dll text section with a clean copy from disk or KnownDlls
- **PE stomping** — overwrite an existing legitimate module's memory instead of allocating new
- **Gargoyle / floating code** — disguise RWX memory as RX with periodic re-encryption
- **DLL side-loading** — place a malicious DLL next to a legitimate signed executable
- **Heaven's gate** — 32-bit implant transitions to 64-bit syscalls to evade 32-bit hooks

### Persistence (Windows)
- **Registry Run key** — HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- **Scheduled task** — schtasks XML or COM-based task creation
- **WMI event subscription** — permanent WMI subscription triggered on logon/timer
- **COM hijacking** — override a per-user CLSID to point at a payload DLL
- **Startup folder** — drop LNK or script in shell:startup

### Persistence (Linux)
- **Crontab** — user or system cron entry
- **Systemd user unit** — `~/.config/systemd/user/` service
- **LD_PRELOAD** — shared library injected into every new process
- **Profile / rc hooks** — .bashrc, .zshrc, /etc/profile.d/ entries
- **SUID abuse** — create/exploit SUID binary for privilege re-entry

### Privilege escalation (Linux)
- **sudo -l enumeration** — list exploitable sudo rules
- **SUID binary scan** — find world-executable SUID binaries against a known-exploit list
- **Capabilities scan** — `getcap -r /` to find cap_setuid or cap_net_raw binaries
- **Writable cron / PATH** — detect writable cron scripts or $PATH entries

---

## Transport / C2 Channels

- **DNS C2** — encode data in TXT/A queries; suitable for highly restricted networks
- **DNS-over-HTTPS (DoH)** — tunnel DNS traffic through HTTPS to evade DNS inspection
- **ICMP C2** — data in ICMP echo payloads; low-profile on permissive networks
- **SMB named-pipe C2** — peer-to-peer channel between implants, one acts as egress proxy
- **WebSocket C2** — persistent bidirectional channel; harder to fingerprint than polling
- **HTTPS with domain fronting** — route traffic via a CDN edge host to hide true destination
- **Azure/AWS/GCP function fronting** — serverless function as a one-hop redirector
- **Slack / Teams / Discord exfil** — use legitimate SaaS APIs as covert channels
- **Email C2** — commands in email subjects/bodies; useful in airgapped-adjacent scenarios
- **Multiplexed channels** — switch between transports mid-operation based on operator command

---

## Server

- **Multi-operator RBAC** — roles: admin, operator, viewer; per-session locking
- **Real-time push** — WebSocket or SSE stream for live session/task events in the client
- **Listener management** — create/delete/configure HTTP listeners from the operator UI
- **Malleable C2 profiles** — per-listener URI patterns, headers, jitter, transforms
- **Payload generator** — server-side build system (cross-compile, sign, obfuscate, deliver)
- **Event log** — append-only audit trail of all operator actions and implant events
- **Screenshots gallery** — view and download captured screenshots in the operator UI
- **Credential vault** — store harvested creds (hashes, cleartext, tickets) per engagement
- **Session graph** — visualise network topology from pivot and lateral movement data
- **Loot store** — structured storage for files, keys, tokens collected from implants
- **REST API** — documented HTTP API for external tool integration (Cobalt Strike aggressor-style)
- **Webhook notifications** — POST to Slack/Teams/Discord on new session or task completion

---

## Infrastructure / DevOps

- **Ansible playbooks** — deploy server, redirectors, and Postgres to VPS targets
- **Terraform modules** — provision cloud infrastructure (VPS, DNS, CDN) for an engagement
- **Automated redirector provisioning** — spin up DigitalOcean/Linode redirectors via API
- **TLS certificate automation** — Let's Encrypt via ACME for redirectors and server
- **mTLS operator channel** — mutual TLS between client and gRPC server for operator auth
- **Grafana + Prometheus** — metrics dashboard: active sessions, task throughput, error rates
- **Log shipping** — forward structured logs to an ELK/Loki stack for analysis
- **CI/CD pipeline** — GitHub Actions: build implant artifacts, run tests, publish releases
- **Signing** — Authenticode signing for Windows implants; codesign for macOS

---

## Operator Client

- **Interactive shell** — true PTY (pseudoterminal) over the C2 channel, tab completion
- **VIM/Nano-style file editor** — edit remote files in-place
- **Session tagging and notes** — per-session labels, hostnames, targets, operator notes
- **Task templates** — save recurring task sequences as named scripts
- **Theming** — switchable colour themes (dark/light/custom)
- **Multi-pane layout** — split view: sessions + terminal + task history side by side
- **Operator chat** — in-band messaging between concurrent operators
