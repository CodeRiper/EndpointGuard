#!/usr/bin/env bash
# ==============================================================================
# EndpointGuard Enterprise Server — Linux Turnkey Installer & CLI Setup
# ==============================================================================
# Usage:
#   sudo ./install-server.sh                     # Standard installation
#   sudo ./install-server.sh --setup             # Interactive CLI onboarding wizard
#   sudo ./install-server.sh --admin-password <pass> --bind <localhost|network>
# ==============================================================================
set -euo pipefail

HTTP_PORT=8080
GRPC_PORT=4443
BIND_MODE="network"
STORAGE_DIR="/var/log/endpointguard"
INSTALL_DIR="/opt/endpointguard"
CONFIG_DIR="/etc/endpointguard"
ADMIN_PASSWORD=""
RUN_SETUP=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup) RUN_SETUP=true; shift ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift 2 ;;
    --bind) BIND_MODE="$2"; shift 2 ;;
    --storage-dir) STORAGE_DIR="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --grpc-port) GRPC_PORT="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "[-] Please run as root (sudo ./install-server.sh)." >&2
  exit 1
fi

echo "======================================================================="
echo "   🛡️  EndpointGuard Enterprise Control Server — Linux Installer"
echo "======================================================================="

# Locate binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_SRC=""
for candidate in "$SCRIPT_DIR/server/eg-server-linux" "$SCRIPT_DIR/eg-server-linux" "$SCRIPT_DIR/server/eg-server"; do
  if [[ -f "$candidate" ]]; then
    BINARY_SRC="$candidate"
    break
  fi
done

if [[ -z "$BINARY_SRC" ]]; then
  echo "[-] Server binary not found. Building with Go..."
  if command -v go >/dev/null 2>&1; then
    (cd "$SCRIPT_DIR/server" && GOOS=linux GOARCH=amd64 go build -o eg-server-linux ./cmd/server)
    BINARY_SRC="$SCRIPT_DIR/server/eg-server-linux"
  else
    echo "[-] Error: Go is not installed and prebuilt eg-server-linux was not found." >&2
    exit 1
  fi
fi

echo "[+] Creating dedicated service user and directories..."
if ! id -u endpointguard >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin endpointguard 2>/dev/null || true
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR/certs" "$STORAGE_DIR/logs" "$STORAGE_DIR/audit" "$STORAGE_DIR/telemetry"
cp "$BINARY_SRC" "$INSTALL_DIR/endpointguard-server"
chmod 755 "$INSTALL_DIR/endpointguard-server"
ln -sf "$INSTALL_DIR/endpointguard-server" /usr/local/bin/endpointguard-server
ln -sf "$INSTALL_DIR/endpointguard-server" /usr/local/bin/eg-server

echo "[+] Copying certificates..."
for cert_dir in "$SCRIPT_DIR/certs" "$SCRIPT_DIR/server/certs"; do
  if [[ -d "$cert_dir" ]]; then
    cp -r "$cert_dir"/* "$CONFIG_DIR/certs/" 2>/dev/null || true
    break
  fi
done

# Generate config.json if not existing
CONFIG_FILE="$CONFIG_DIR/config.json"
cat > "$CONFIG_FILE" <<EOF
{
  "listen_mode": "$BIND_MODE",
  "http_port": "$HTTP_PORT",
  "grpc_port": "$GRPC_PORT",
  "storage_dir": "$STORAGE_DIR",
  "log_retention_days": 30,
  "admin_password": "$ADMIN_PASSWORD",
  "clickhouse_dsn": "clickhouse://localhost:9000/endpointguard",
  "postgres_dsn": "postgres://eg:eg@localhost:5432/endpointguard",
  "tls_cert_file": "$CONFIG_DIR/certs/server.crt",
  "tls_key_file": "$CONFIG_DIR/certs/server.key",
  "client_ca_file": "$CONFIG_DIR/certs/client-ca.crt"
}
EOF
chmod 640 "$CONFIG_FILE"

# Set permissions
chown -R endpointguard:endpointguard "$INSTALL_DIR" "$CONFIG_DIR" "$STORAGE_DIR" 2>/dev/null || true

# Interactive CLI Setup if requested
if [[ "$RUN_SETUP" == true ]]; then
  echo ""
  "$INSTALL_DIR/endpointguard-server" --config "$CONFIG_FILE" --setup
fi

# Create systemd unit file
echo "[+] Configuring systemd service..."
cat > /etc/systemd/system/endpointguard-server.service <<EOF
[Unit]
Description=EndpointGuard Enterprise Control Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=endpointguard
Group=endpointguard
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/endpointguard-server --config $CONFIG_FILE
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$INSTALL_DIR $STORAGE_DIR $CONFIG_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable endpointguard-server.service
systemctl restart endpointguard-server.service || true

# Get Local IP
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo ""
echo "======================================================================="
echo "   ✓ EndpointGuard Server Installed & Running on Linux!"
echo "======================================================================="
echo "   Web Dashboard URL:     http://localhost:$HTTP_PORT"
echo "   LAN Network Access:    http://$HOST_IP:$HTTP_PORT"
echo "   Web Setup Wizard:      http://localhost:$HTTP_PORT/setup"
echo "   Agent Tunnel (gRPC):   $GRPC_PORT"
echo "   Storage Directory:     $STORAGE_DIR"
echo "   Configuration File:    $CONFIG_FILE"
echo ""
echo "   Management CLI Commands:"
echo "     endpointguard-server --status           # Check server status & IPs"
echo "     endpointguard-server --setup            # Run interactive setup wizard"
echo "     endpointguard-server --admin-password X # Change admin password"
echo "     sudo systemctl status endpointguard-server"
echo "     sudo journalctl -u endpointguard-server -f"
echo "======================================================================="

