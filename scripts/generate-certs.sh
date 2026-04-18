#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p certs

openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 825 \
  -out certs/ca.crt -subj "/CN=Wraith Dev CA"

openssl genrsa -out certs/server.key 4096
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=localhost"
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

rm -f certs/*.csr certs/*.srl
echo "root CA and server certificates written to certs/"
