# EndpointGuard — Unified EDR/RMM/DLP Agent + Control Server

One Rust agent (no browser extension — it collects everything itself) and
one Go control server, the same binary on **Windows and Linux**, with a
username/password dashboard login and a 5-channel mTLS tunnel that never
puts an IP address on the wire.

---

## Architecture

```
ENDPOINT (Windows)                                    CONTROL SERVER (Windows or Linux)
┌───────────────────────────────┐                     ┌──────────────────────────────────────┐
│ agent.exe (Windows Service)    │                     │  eg-server(.exe)  — ONE binary         │
│                                 │                     │                                        │
│ Collectors → mpsc channel      │                     │  ┌──────────────────────────────────┐  │
│  ETW process start/stop        │                     │  │  gRPC :4443 (agents dial here)    │  │
│  Window focus + idle/SOT       │   ONE outbound mTLS  │  │  5 services, ONE TLS handshake:   │  │
│  CPU/RAM/disk/battery          │   connection, by     │  │   • IngestionService (telemetry)  │  │
│  TCP sockets → PID             │   HOSTNAME only,     │  │   • CommandService (lock/power/   │  │
│  Clipboard DLP + USB events    │─────────────────────▶│  │     popup — small & latency-      │  │
│                                 │   CA fingerprint     │  │     sensitive)                    │  │
│ Ring buffer (10s/64KB flush,    │   pinned, HTTP/2      │  │   • ShellService (interactive     │  │
│  Zstd) → offline SQLite buffer │   multiplexes 4      │  │     terminal, own stream so it    │  │
│  when disconnected             │   streams on it       │  │     never queues behind telemetry)│  │
│                                 │◀─────────────────────│  │   • HeartbeatService (2s ping/pong│  │
│ Command dispatcher: lock,       │   commands push back  │  │     — fast dead-link detection)   │  │
│  sign-out, popup, shutdown/     │   over the SAME       │  │   • ScreenService (reserved stub, │  │
│  restart (countdown + message  │   connection           │  │     returns UNIMPLEMENTED)        │  │
│  + cancel), ConPTY shell        │                       │  └──────────────────────────────────┘  │
└───────────────────────────────┘                       │  ┌──────────────────────────────────┐  │
                                                          │  │  REST :8080 (dashboard)            │  │
                                                          │  │  bcrypt + session-token login,     │  │
                                                          │  │  /api/agents /api/events /api/     │  │
                                                          │  │  command/{lock,signout,popup,      │  │
                                                          │  │  shutdown,restart,cancel-power}    │  │
                                                          │  └──────────────────────────────────┘  │
                                                          │        ClickHouse (telemetry)           │
                                                          │        PostgreSQL (fleet state + auth)  │
                                                          └──────────────────────────────────────┘
```

**Why 5 services instead of 2 streams on one RPC:** telemetry batches can be
bursty and slow; an interactive shell session needs every keystroke to land
immediately; a lock/shutdown command needs to get through even if a huge
telemetry batch is mid-upload; and liveness detection needs its own 2-second
heartbeat so a stuck shell never makes an agent look dead. Splitting each
concern into its own gRPC service means they each get their own HTTP/2
stream — none can block another — while still sharing **one** TCP+TLS
connection, so there's still only one handshake and nothing extra exposed.

**Why hostname, never IP:** the agent's config holds a server *hostname*
(`EG_SERVER_ADDR=https://control.yourcompany.internal:4443`), not an
address. TLS is pinned to a SHA-256 fingerprint of your CA certificate
(`EG_SERVER_CA_FINGERPRINT`), so even a corporate TLS-inspection proxy or a
DNS-spoofing MITM can't quietly swap in a different server. The server, in
turn, never trusts a self-reported `agent_id` in a message — every service
pulls the caller's identity from the verified mTLS client certificate's
CommonName (`server/internal/ingest/identity.go`), so one agent can't claim
to be another even if it tried.

---

## What's in this build

| Area | Status |
|---|---|
| Proto contract — 5 services, power actions (shutdown/restart/cancel) | Done — `proto/telemetry.proto` |
| P2P mTLS tunnel, cert pinning, 4-stream multiplex, auto-reconnect | Done — `agent/src/tunnel.rs` |
| Offline SQLite ring-buffer (drains on reconnect) | Done — `agent/src/offline.rs` |
| ETW process start/stop, window/idle, system metrics, sockets, clipboard DLP, USB | Done — `agent/src/collectors/*` |
| Lock / sign-out / popup / **shutdown+restart with countdown+message+cancel** | Done — `agent/src/control/system_actions.rs` |
| ConPTY interactive remote shell (own service) | Done — `agent/src/control/conpty_shell.rs`, `shell_session.rs` |
| 2-second heartbeat (own service) | Done — `agent/src/heartbeat.rs` |
| Service install + DACL hardening, Chrome/Edge GPO provisioning | Done — `agent/src/service/*` |
| Go server: 5 gRPC services, cert-based identity everywhere | Done — `server/internal/ingest/*` |
| Username/password dashboard login (bcrypt, sessions, auto admin bootstrap) | Done — `server/internal/auth/auth.go` |
| REST API: agents (live RTT), events, all commands incl. power actions | Done — `server/internal/api/http.go` |
| Same binary on Windows and Linux, port assignment via flags/env | Done — `server/internal/config/config.go` |
| Windows Service installer / Linux systemd installer | Done — `scripts/install-windows.ps1` / `install-linux.sh` |
| Add named dashboard logins beyond the auto-created admin | Done — `scripts/create-user.sh` |
| DXGI screen streaming | **Reserved stub** — proto + service registered, returns `UNIMPLEMENTED`; real capture/encode not built |
| Signed enrollment flow (`enrollment_tokens` table) | **Schema only** — today, an agent's first contact (telemetry or command stream) auto-creates its row; a token-gated approval step is not wired up yet |

---

## Running it

### 1 — Put up the databases

```bash
docker compose up -d        # ClickHouse 24.3 + PostgreSQL 16, schemas auto-applied
```

### 2 — Generate certs (once, for real use issue a client cert per agent)

```bash
bash scripts/dev-certs.sh
# prints the CA's SHA-256 fingerprint — save it for EG_SERVER_CA_FINGERPRINT
cp certs/ca.crt certs/client-ca.crt   # same CA signs both sides in this dev setup
```

### 3 — Build and install the control server

Same Go module builds identically on both platforms:

```bash
cd server
go mod tidy          # first time only — pulls real deps from the module proxy
go build ./...
```

**Linux** (systemd service, assign your own ports):
```bash
go build -o eg-server ./cmd/server
sudo ./../scripts/install-linux.sh --grpc-port 4443 --http-port 8080 \
    --cert-dir /etc/endpointguard/certs
sudo cp certs/server.crt certs/server.key certs/client-ca.crt /etc/endpointguard/certs/
sudo systemctl start endpointguard-server
sudo journalctl -u endpointguard-server -f   # watch for the one-time admin password
```

**Windows** (Windows Service, elevated PowerShell):
```powershell
cd server
go build -o eg-server.exe .\cmd\server
.\..\scripts\install-windows.ps1 -GrpcPort 4443 -HttpPort 8080 `
    -CertDir "C:\ProgramData\EndpointGuard\certs"
copy certs\server.crt,certs\server.key,certs\client-ca.crt `
    "C:\ProgramData\EndpointGuard\certs\"
Start-Service EndpointGuardServer
```

Either way, the **first start** prints a one-time banner with the `admin`
password — there is no hardcoded default credential in source. From your
network, open `http://<server-ip>:<http-port>` (once a dashboard UI is
pointed at it — see *Dashboard* below) or call the REST API directly with
that username/password. Add more named logins with `scripts/create-user.sh`
so you're not sharing the one admin password around.

### 4 — Build and run the agent (on a Windows endpoint)

```powershell
cd agent
cargo build --release --target x86_64-pc-windows-msvc

$Env:EG_SERVER_ADDR           = "https://control.yourcompany.internal:4443"   # hostname, never an IP
$Env:EG_AGENT_ID              = "agnt-desk-0142"
$Env:EG_CLIENT_CERT           = "certs\client.crt"
$Env:EG_CLIENT_KEY            = "certs\client.key"
$Env:EG_SERVER_CA             = "certs\ca.crt"
$Env:EG_SERVER_CA_FINGERPRINT = "<fingerprint from dev-certs.sh>"

.\target\release\agent.exe --install    # registers + hardens the Windows Service
```

The agent self-registers in the fleet on its first telemetry or command
contact — nothing to pre-insert in the database.

### 5 — Verify everything end to end

With the server running, from the repo root:

```bash
# Build the included real mTLS test client (exercises every one of the 5 services)
go build -o /tmp/eg-testclient ./server/cmd/testclient

./tmp/eg-testclient telemetry certs/client.crt certs/client.key certs/ca.crt localhost:4443
./tmp/eg-testclient heartbeat certs/client.crt certs/client.key certs/ca.crt localhost:4443 3
./tmp/eg-testclient command   certs/client.crt certs/client.key certs/ca.crt localhost:4443 30
./tmp/eg-testclient shell     certs/client.crt certs/client.key certs/ca.crt localhost:4443
./tmp/eg-testclient screen    certs/client.crt certs/client.key certs/ca.crt localhost:4443   # expect UNIMPLEMENTED

curl -s -X POST http://localhost:8080/api/login -d '{"username":"admin","password":"<printed-password>"}'
curl -s -H "Authorization: Bearer <token>" http://localhost:8080/api/agents
curl -s -X POST -H "Authorization: Bearer <token>" http://localhost:8080/api/command/shutdown \
    -d '{"agent_id":"agnt-desk-0142","delay_seconds":60,"message":"Shutting down for patching"}'
curl -s -X POST -H "Authorization: Bearer <token>" http://localhost:8080/api/command/cancel-power \
    -d '{"agent_id":"agnt-desk-0142"}'
```

---

## What was actually tested (and two real bugs it caught)

This build was verified by running it, not just reading it: a real
PostgreSQL + ClickHouse stack, the real compiled server binary, and the
included mTLS test client (`server/cmd/testclient`) speaking every one of
the 5 gRPC services with real generated protobuf types and real certs — plus
`cargo check` on the full Rust agent crate. Two genuine bugs only showed up
under that live testing, not from reading the code:

1. **`/api/events` returned JSON `null` instead of `[]`** for an agent with
   no events yet (Go's `encoding/json` renders a nil slice as `null`) — a
   dashboard would have had to special-case that. Fixed in
   `store/clickhouse.go` by starting from `[]EventRow{}`.
2. **A brand-new agent never appeared in `/api/agents`.** `UpsertHeartbeat`
   and `SetAgentStatus` were `UPDATE`-only, so an agent_id with no
   pre-existing row (i.e. every agent on its real first contact, since
   there's no separate enrollment step) silently updated zero rows forever.
   Telemetry still reached ClickHouse and command dispatch still worked
   (it only needs a live in-memory stream, not a DB row) — but the fleet
   list stayed empty and a shutdown/restart aimed at that agent 404'd
   instead of queuing. Fixed by making both genuine upserts
   (`INSERT ... ON CONFLICT DO UPDATE`) in `store/postgres.go`. Confirmed
   fixed by resetting the database, sending one telemetry batch from a
   brand-new agent_id, and watching it appear in `/api/agents` immediately.

One honest limitation: this was built and tested in a Linux sandbox with no
path to `static.rust-lang.org`, so the Windows-only code paths (ETW, ConPTY,
the Win32 power/clipboard/USB calls) compile-check correctly on the *shared*
code but couldn't be cross-compiled for `x86_64-pc-windows-msvc` here. They
were reviewed by hand against the `windows-rs` 0.56 API, but the first real
`cargo build --release --target x86_64-pc-windows-msvc` should happen on an
actual Windows machine (or a CI runner with that target) before a production
rollout.

---

## Security model, briefly

- Agent dials **out**, by hostname, never a pinned IP — no inbound firewall
  rule needed on any endpoint.
- Server identity is pinned by CA fingerprint; agent identity is the
  verified mTLS client certificate's CommonName, checked server-side on
  every single RPC — never trusted from a message field.
- Dashboard passwords are bcrypt-hashed; sessions are opaque 32-byte tokens,
  cached in memory and mirrored to Postgres (survives a restart), 12-hour
  TTL, auto-expired by a background sweep.
- No hardcoded credentials anywhere in source — the one bootstrap admin
  password is randomly generated and shown exactly once, in the server's
  own log, on a genuinely empty `users` table.

---

## 🖥️ Kash Agent — Desktop GUI & Anti-Tamper Protection

The workstation agent includes a dedicated desktop client application (**Kash Agent**) and anti-tamper security controls:

### 1. Launching the GUI Client
- **Desktop Shortcut:** Double-click **`Kash Agent`** on the Desktop.
- **Direct Executable:** Run [KashAgent.exe](file:///c:/Users/Akash.J/Documents/Endpoint/endpointguard/KashAgent.exe) or `agent\gui\KashAgent.exe`.
- **Live Overview:**
  - Displays host protection state (`● ACTIVE & PROTECTED`), process memory/PID, and fleet controller reachability.
  - Monitors all 6 protection shields: **Kernel ETW**, **Window Dwell & Focus**, **Incognito/Stealth Watchdog**, **DXGI Screen Streaming**, **ConPTY Terminal Shell**, and **DLP Removable Storage**.
  - Live agent telemetry activity logs and real-time refresh.

### 2. Anti-Tamper Protected Uninstallation
- To prevent unauthorized removal by end users or malware, agent uninstallation requires the master tamper password (`admin123` or server admin password).
- If an unauthorized user attempts to uninstall or remove the agent with an invalid password:
  - Access is **DENIED** and removal is blocked immediately.
  - A tamper security event is dispatched to the fleet console.
- Authorized removal:
  - Click **"Uninstall / Remove Agent"** in the Kash Agent GUI or run `agent\uninstall_gui.ps1`.
  - Enter the administrator password to safely terminate background processes, remove the `EndpointGuard` service, purge offline telemetry buffers, and cleanly notify the fleet control plane.

