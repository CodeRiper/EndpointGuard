#!/usr/bin/env bash
set -e

echo "[+] Generating extension config..."
cat > /tmp/server_ext.cnf << 'EOF'
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = control.endpointguard.internal
DNS.3 = *.endpointguard.internal
DNS.4 = endpointguard
IP.1 = 127.0.0.1
IP.2 = 192.168.102.105
IP.3 = 192.168.29.19
IP.4 = 100.127.255.220
IP.5 = 0.0.0.0
EOF

echo "[+] Signing server.crt with CA..."
openssl x509 -req -in /etc/endpointguard/certs/server.csr \
  -CA /etc/endpointguard/certs/ca.crt \
  -CAkey /etc/endpointguard/certs/ca.key \
  -CAcreateserial \
  -out /etc/endpointguard/certs/server.crt \
  -days 3650 \
  -extfile /tmp/server_ext.cnf

chown endpointguard:endpointguard /etc/endpointguard/certs/server.crt
chmod 644 /etc/endpointguard/certs/server.crt
echo "[+] Verification:"
openssl x509 -in /etc/endpointguard/certs/server.crt -noout -ext subjectAltName
