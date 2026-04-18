# Wraith Orchestrator

Rust workspace for a safe orchestration system with:

- `server`: headless gRPC control plane secured with mTLS, plus separate HTTPS enrollment and operator login endpoints
- `client`: native GUI operator application with a start page for certificate enrollment and username/password login before the main console
- `agent`: HTTP service that executes typed allowlisted maintenance jobs

## Safe job model

The agent does not execute arbitrary shell commands. It only supports:

- health checks
- metrics collection
- bounded log retrieval from configured files

## Enrollment model

- The client generates its private key locally and submits a CSR on first enrollment.
- The server signs the CSR with the configured root CA private key.
- Enrollment requires an enrollment token from [examples/enrollment-tokens.json](/home/user/Desktop/WraithC2/examples/enrollment-tokens.json).
- Normal operator traffic is only accepted over gRPC with mTLS after enrollment.

## Operator authentication

- Device trust is established with the enrolled client certificate.
- Operator identity is established separately with username/password over HTTPS.
- The GUI client only unlocks the main page after both checks succeed.
- The server stores users and sessions in SQLite.
- Passwords are stored as `Argon2id` hashes.
- gRPC requests require both a valid client certificate and a valid bearer session token.

Sample enrollment token for local development:

```text
wraith-enrollment-dev-2026
```

## Database

The server uses a local SQLite database file for auth and session state.

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

5. Start the GUI client:

   ```bash
   cargo run -p client
   ```

6. In the GUI:

   Use enrollment token `wraith-enrollment-dev-2026`, enroll the device, then log in with the provisioned admin password. After both are complete, enter the main page, refresh the dashboard, and dispatch jobs from the client window.
