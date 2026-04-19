# Wraith Ansible Deployment

This playbook deploys the current Rust workspace onto VPS hosts with:

- `server` as a `systemd` service on control-plane nodes
- `agent` as a `systemd` service on agent nodes
- optional WireGuard on control-plane nodes for operator VPN access
- optional NGINX redirectors for the control-plane-to-agent HTTP hop

## What It Assumes

- You run Ansible from this repository checkout.
- Target hosts are Debian/Ubuntu-style systems with outbound package access.
- The control plane remains single-writer unless you provide shared state yourself.
- You will explicitly define allowed source CIDRs for control-plane and redirector exposure.

The redirector role can balance traffic across multiple backends, but the current server design is not safe for active-active control planes by default because it uses local SQLite, local enrollment-token state, and a local CA key. Load balancing across multiple servers only makes sense if you first externalize and share that state.

## Layout

- `site.yml`: main playbook
- `group_vars/all.yml`: global defaults
- `inventories/example/hosts.yml`: example inventory

## Quick Start

1. Copy the example inventory and replace hostnames/IPs.
2. Set `wraith_server_catalog`, `wraith_enrollment_tokens`, and the agent registration vars for your environment.
3. Run:

```bash
cd deploy/ansible
ansible-playbook -i inventories/example/hosts.yml site.yml
```

## TLS Modes

By default, the control-plane role generates a local CA and server cert on the target host:

```yaml
wraith_server_tls_mode: self_signed
```

If you already have PEM files on the Ansible controller, switch to:

```yaml
wraith_server_tls_mode: provided
wraith_provided_ca_cert_src: /path/to/ca.crt
wraith_provided_ca_key_src: /path/to/ca.key
wraith_provided_server_cert_src: /path/to/server.crt
wraith_provided_server_key_src: /path/to/server.key
```

To run the control plane without the CA key online:

```yaml
wraith_server_offline_ca: true
```

## Redirector Blueprints

Redirectors proxy the plain HTTP server-to-agent path. They are not in front of the operator-facing control plane in the VPN-only topology.

Use `wraith_redirector_blueprints` as the routing blueprint. Each entry defines one named listener and backend pool:

```yaml
wraith_redirector_blueprints:
  - name: agent-http
    listen: 0.0.0.0:8088
    balance: least_conn
    auth_token: replace-with-a-shared-redirector-token
    allowed_cidrs:
      - 10.0.0.11/32
    proxy_set_headers:
      X-Wraith-Route: agent-http
    backends:
      - name: agent1
        address: 10.0.10.21:8088
      - name: agent2
        address: 10.0.10.22:8088
```

This makes the redirector traffic modular:

- change listeners without editing templates
- define multiple named routes on one redirector
- swap balancing policy per route
- require a per-route shared token from the control plane
- attach static proxy headers per route
- point a route at any backend pool you want

The older single-route vars are still accepted as a compatibility fallback:

- `wraith_redirector_bind_agent_http`
- `wraith_redirector_balance`
- `wraith_redirector_agent_backends`
- `wraith_redirector_allowed_agent_cidrs`

## Network Boundary

The playbook now enforces:

- `ufw` on control-plane nodes so `50051/tcp` and `5443/tcp` are only reachable from the VPN CIDRs you allow
- `ufw` on redirector nodes so only SSH plus the blueprint listener ports are exposed
- NGINX allow/deny rules on redirectors so only approved control-plane CIDRs can use each blueprint route

Typical setup:

- Operators connect to WireGuard on the control plane
- The client application reaches the control plane over the VPN
- The control plane calls redirectors on the server-to-agent hop
- Redirectors forward to agents

## Redirector And Agent Tokens

If a blueprint sets `auth_token`, NGINX only forwards requests that include the matching `X-Wraith-Redirector-Token` header.

The control plane sends that header when the target agent entry has `redirector_token` set in the server catalog or DB seed.

For the plain HTTP control-plane-to-agent path, the application now supports a shared header token:

- server catalog entries can include `auth_token`
- server catalog entries can include `redirector_token`
- agent config can include `auth_token`
- redirector blueprints can include `auth_token`
- the control plane sends `X-Wraith-Redirector-Token` to the redirector and `X-Wraith-Agent-Token` to the agent
- the agent rejects requests without the expected value

This is the right primitive for this path. A browser-style cookie would also be just another header here, but a dedicated service header is clearer.

## Agent Registration

Agent hosts can now self-register against the control plane. Relevant vars in `group_vars/all.yml` are:

- `wraith_agent_control_plane_url`
- `wraith_agent_bootstrap_token`
- `wraith_agent_state_path`
- `wraith_agent_advertised_base_url`
- `wraith_agent_commands`

The first start uses the bootstrap token. After that, the agent keeps its stable identity plus control-plane-issued tokens in `wraith_agent_state_path`.

If you want the control plane to target redirectors instead of direct agent IPs, point the agent endpoint or seeded server catalog entry at the redirector blueprint listener address.

## Token Requirement

The plain HTTP control-plane-to-agent leg uses the shared `X-Wraith-Agent-Token` header. Redirectors forward that header through to the agent, and the agent rejects unauthenticated requests.

## Environment Files

The playbook installs service env files for `systemd`:

- `/etc/wraith/server.env` for the control plane
- `/etc/wraith/agent.env` for agents

This is acceptable if they are treated like secrets:

- root-owned
- not world-readable
- distributed only over Ansible

They are good for simple runtime values such as `DATABASE_URL` or logging flags. They are not a good replacement for structured data like the agent catalog or enrollment token store, so those remain JSON templates.

## WireGuard

Set these on control-plane hosts to make operators VPN-only:

```yaml
wraith_wireguard_enabled: true
wraith_wireguard_server_private_key: replace-with-server-private-key
wraith_wireguard_server_address: 10.8.0.1/24
wraith_wireguard_peers:
  - name: operator-laptop
    public_key: replace-with-operator-public-key
    allowed_ips:
      - 10.8.0.10/32
```

## Notes

- The playbook uploads this repository to each build host and compiles there with `cargo build --release`.
- Client deployment is intentionally not automated here because the current client is a desktop GUI.
- Enrollment token usage and enrolled-client state are now persisted in SQLite.
- The implemented routing is `client -> control plane over VPN -> redirector -> agent`.
- The current firewall tasks rebuild `ufw` rules during each run to keep the host policy explicit and narrow.

## Offline CA Automation

If `wraith_server_offline_ca: true`, the live server accepts enrollment requests but does not sign them. Use the application commands to automate a batch flow:

```bash
cargo run -p server -- export-pending-enrollments --out-dir outbox
cargo run -p server -- sign-enrollment-bundle --input outbox/<request-id>.json --output signed/<request-id>.json --ca-cert /path/to/ca.crt --ca-key /path/to/ca.key --mtls-endpoint https://control-plane.example.com:50051
cargo run -p server -- import-signed-enrollment --input signed/<request-id>.json
```

The practical automation pattern is:

- export pending bundles on the live control plane
- move them to the offline CA host through your approved transfer path
- sign there
- move signed bundles back
- import them on the live control plane

If you want this fully hands-off, the next step would be an explicit inbox/outbox watcher service rather than more Ansible.
