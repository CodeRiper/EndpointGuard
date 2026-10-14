#!/usr/bin/env bash
# dev-certs.sh — generate a self-signed CA, server cert, and one
# client cert for local testing.  Never use in production.
set -euo pipefail

OUT="certs"
mkdir -p "$OUT"
cd "$OUT"

echo "== CA =="
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=EndpointGuard Dev CA"

echo "== Server cert =="
openssl req -newkey rsa:4096 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 3650 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

echo "== Client cert (agnt-test-001) =="
openssl req -newkey rsa:4096 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=agnt-test-001"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 3650

echo ""
echo "CA fingerprint (set as EG_SERVER_CA_FINGERPRINT):"
openssl dgst -sha256 -binary ca.crt | xxd -p | tr -d '\n'
echo ""
echo "Done — certs in ./certs/"
