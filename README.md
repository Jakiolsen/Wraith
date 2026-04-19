# Wraith Orchestrator

Rust workspace for a safe orchestration system with:

- `server`: headless gRPC control plane secured with mTLS, plus separate HTTPS enrollment and operator login endpoints
- `client`: native GUI operator application with a start page for certificate enrollment and username/password login before the main console
- `agent`: HTTP service that executes typed allowlisted maintenance jobs

## Safe job model

The agent executes a modular allowlist of actions:

- health checks
- metrics collection
- bounded log retrieval from configured files
- operator-invoked modules from the agent's explicit `commands` config

The control plane attaches a per-agent `X-Wraith-Agent-Token` header when talking to agents. Agents reject requests that do not include the current inbound token.

If the control plane talks to agents through an HTTP redirector, agent records can also carry a `redirector_token`. The control plane sends that as `X-Wraith-Redirector-Token`, and the redirector can reject unauthenticated callers before forwarding to the agent.

## Enrollment model

- The client generates its private key locally and submits a CSR on first enrollment.
- The server can either sign the CSR immediately or store it as a pending request for offline CA approval.
- Enrollment requires an enrollment token from [examples/enrollment-tokens.json](/home/user/Desktop/Wraith/examples/enrollment-tokens.json).
- Normal operator traffic is only accepted over gRPC with mTLS after enrollment.

## Operator authentication

- Device trust is established with the enrolled client certificate.
- Operator identity is established separately with username/password over HTTPS.
- The GUI client only unlocks the main page after both checks succeed.
- The server stores users and sessions in SQLite.
- Passwords are stored as `Argon2id` hashes.
- gRPC requests require both a valid client certificate and a valid bearer session token.
- The server binds gRPC access to an enrolled client certificate fingerprint stored in SQLite.

Sample enrollment token for local development:

```text
wraith-enrollment-dev-2026
```

## Database

The server uses a local SQLite database file for auth, sessions, enrollment requests, token usage, enrolled-device state, bootstrap tokens, and registered-agent inventory.

By default, the database file is:

```text
sqlite://data/wraith_orchestrator.db
```

The server creates the database file automatically if it does not exist.

You can still override the location with `DATABASE_URL` or `--database-url` when needed.

Create the initial admin user with a separate one-time provisioning command. The server generates a random 64-character password, stores only the `Argon2id` hash in SQLite, and prints the generated password once:

```bash
cargo run -p server -- provision-admin --username admin
```

If you need to replace an existing admin password intentionally:

```bash
cargo run -p server -- provision-admin --username admin --rotate
```

## Local run

1. Generate development certificates:

   ```bash
   ./scripts/generate-certs.sh
   ```

2. Start the agent:

   ```bash
   cargo run -p agent -- --config examples/agent.json
   ```

   The first start requires a bootstrap token from the operator UI or the HTTPS admin API. After registration, the agent stores its stable identity and tokens in `data/agent.state.json`.

3. Provision the initial admin user.
   
   No separate database service is required. The server will create `data/wraith_orchestrator.db` on first start.

   ```bash
   cargo run -p server -- provision-admin --username admin
   ```

4. Start the server:

   ```bash
   cargo run -p server -- \
     --catalog examples/agents.json \
     --enrollment-tokens examples/enrollment-tokens.json
   ```

   To keep the CA key offline while still accepting enrollment requests:

   ```bash
   cargo run -p server -- \
     --offline-ca \
     --catalog examples/agents.json \
     --enrollment-tokens examples/enrollment-tokens.json
   ```

5. Start the GUI client:

   ```bash
   cargo run -p client
   ```

6. In the GUI:

   Use enrollment token `wraith-enrollment-dev-2026`, enroll the device, then log in with the provisioned admin password. After both are complete, enter the main page, issue an agent bootstrap token, register the agent, refresh the dashboard, and dispatch jobs from the client window.

## Agent lifecycle

- Operators create one-time agent bootstrap tokens from the UI.
- Agents register over HTTPS with that bootstrap token and receive:
  - a stable `agent_id`
  - a management token for heartbeats
  - an inbound auth token for control-plane-to-agent HTTP
- The control plane stores registered agents in SQLite and the dashboard reads from that live inventory.
- Operators can disable an agent or rotate its inbound auth token from the UI.

Static `examples/agents.json` entries are now only seed records for local bootstrap or migration. Live status and capabilities come from the database.

## Roles And Audit

The control plane now enforces three roles:

- `viewer`: dashboard access only
- `operator`: dashboard plus job dispatch
- `admin`: operator access plus bootstrap-token issuance, agent disable, token rotation, and audit view

Create non-admin users with:

```bash
cargo run -p server -- provision-user --username alice --role operator
```

Sensitive actions are written to the SQLite `audit_log` table and exposed to admin users in the UI and at `GET /api/v1/audit`.

## Command Modules

Agent modules are intentionally declarative. Each entry can be a shell command or file collection module, with optional:

- `supported_platforms`
- `arg_schema`
- `concurrency_limit`
- `allow_args`
- `timeout_seconds`
- `max_output_bytes`

Example shell module:

```json
{
  "id": "uptime",
  "description": "Show system uptime",
  "kind": "shell_command",
  "program": "uptime",
  "supported_platforms": ["linux"],
  "allow_args": false
}
```

Example file collection module:

```json
{
  "id": "collect_example_log",
  "description": "Collect the example application log",
  "kind": "file_collection",
  "base_directory": "examples",
  "source_path": "application.log",
  "allow_args": false,
  "max_output_bytes": 8192
}
```

File collection results are returned to the operator as bounded base64 content plus file metadata and SHA-256.

## Offline CA

When the server runs with `--offline-ca`, enrollment works as a queued workflow:

1. The client submits an enrollment request and stores its private key locally.
2. The server records the request in SQLite and returns `pending`.
3. Export pending requests:

   ```bash
   cargo run -p server -- export-pending-enrollments --out-dir outbox
   ```

4. On the offline CA host, sign a bundle:

   ```bash
   cargo run -p server -- sign-enrollment-bundle \
     --input outbox/<request-id>.json \
     --output signed/<request-id>.json \
     --ca-cert /path/to/ca.crt \
     --ca-key /path/to/ca.key \
     --mtls-endpoint https://control-plane.example.com:50051
   ```

5. Import the signed bundle back on the live server:

   ```bash
   cargo run -p server -- import-signed-enrollment --input signed/<request-id>.json
   ```

6. In the client, use `Check Pending Enrollment` to fetch the issued certificate.

Automation path:

- export pending requests on a timer from the live server
- transfer the JSON bundles to the offline signer through your existing secure process
- sign them on the offline CA machine
- transfer signed bundles back
- run `import-signed-enrollment` on a timer or from a watched inbox directory

That keeps the CA key off the live server while still letting enrollment be mostly automated.

## VPS deployment

An Ansible deployment scaffold is included under [deploy/ansible/README.md](/home/user/Desktop/Wraith/deploy/ansible/README.md).

It supports:

- control-plane deployment as a `systemd` service
- agent deployment as a `systemd` service
- optional NGINX redirectors doing TCP passthrough for gRPC mTLS and HTTPS

Redirectors can distribute traffic across multiple backends, but the current control plane is still single-node by design unless you externalize shared state like the database, enrollment-token usage, and CA material.
