#!/bin/sh
set -e

if [ -f /run/secrets/redirector_token ]; then
    TOKEN=$(cat /run/secrets/redirector_token)
    if [ -n "$TOKEN" ]; then
        export WRAITH_REDIRECTOR_TOKEN="$TOKEN"
    fi
fi

exec "$@"
