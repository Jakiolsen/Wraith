#!/bin/sh
set -e

# Read credentials from Docker secret files and construct DATABASE_URL.
# Secrets are mounted at /run/secrets/ — never passed as environment variables.

if [ ! -f /run/secrets/postgres_password ]; then
    echo "ERROR: /run/secrets/postgres_password not found" >&2
    exit 1
fi

PG_PASS=$(cat /run/secrets/postgres_password)

if [ -z "$PG_PASS" ]; then
    echo "ERROR: postgres_password secret is empty" >&2
    exit 1
fi

export DATABASE_URL="postgres://wraith:${PG_PASS}@postgres:5432/wraith"

if [ -f /run/secrets/redirector_token ]; then
    REDIRECTOR_TOKEN=$(cat /run/secrets/redirector_token)
    if [ -n "$REDIRECTOR_TOKEN" ]; then
        export REDIRECTOR_TOKEN
    fi
fi

if [ -f /run/secrets/ca_passphrase ]; then
    CA_PASSPHRASE=$(cat /run/secrets/ca_passphrase)
    if [ -n "$CA_PASSPHRASE" ]; then
        export CA_PASSPHRASE
    else
        # Empty passphrase file — inject the dev flag so the server starts with a warning
        # instead of refusing. Set a real passphrase in production.
        set -- "$@" --dev-no-passphrase
    fi
else
    set -- "$@" --dev-no-passphrase
fi

exec "$@"
