Generate local development certificates with:

```bash
./scripts/generate-certs.sh
```

The server expects:

- `certs/ca.crt`
- `certs/ca.key`
- `certs/server.crt`
- `certs/server.key`

Client credentials are generated on first enrollment by the `client` binary and written to:

- `certs/client.crt`
- `certs/client.key`
