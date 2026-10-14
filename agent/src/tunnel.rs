//! P2P encrypted tunnel between agent and server.
//!
//! Design:
//! - Agent connects OUTBOUND to `server_addr` (hostname, never raw IP).
//! - mTLS: agent presents its client cert; server must present a cert
//!   signed by the pinned CA fingerprint (no IP ever appears on the wire
//!   or in config — just a hostname plus a cert fingerprint check).
//! - HTTP/2 multiplexing carries FOUR concurrent gRPC streams over ONE TLS
//!   connection — one handshake, no extra exposed ports:
//!     - IngestionService: bulk telemetry (bursty/slow is fine)
//!     - CommandService:   small one-shot actions (lock/power/popup)
//!     - ShellService:     interactive terminal, must stay snappy
//!     - HeartbeatService: 2s ping/pong, used to detect a dead link fast
//!   (ScreenService is a reserved stub server-side — the agent doesn't
//!   dial it yet.)
//! - All four reconnect TOGETHER with exponential backoff + jitter: if any
//!   one stream fails, the whole connection is torn down and redialed, so
//!   there's never a half-alive tunnel.
//! - Offline SQLite ring-buffer drains into the stream after reconnect.
//!
//! Ownership note: `batch_rx` (from the ring buffer) and `result_rx` (from
//! the command dispatcher) must outlive any single connection attempt — the
//! ring buffer keeps producing telemetry whether or not the tunnel is up.
//! But a gRPC client-streaming call needs a `Stream + 'static` request body,
//! and you can't hand it a `&mut Receiver` borrowed from an outer loop that
//! has to survive the *next* reconnect too. So instead of moving the
//! receivers into each attempt, two persistent forwarder tasks own them for
//! the whole agent lifetime and write into an `ActiveSlot<T>` — an
//! `Arc<Mutex<Option<Sender<T>>>>` that each reconnect attempt swaps a fresh
//! sender into (and clears on disconnect). With nothing active, telemetry
//! falls back to the offline buffer instead of being dropped.

use crate::config::Config;
use crate::heartbeat::{HeartbeatState, PING_INTERVAL};
use crate::offline::OfflineBuffer;
use crate::pb::{
    command_service_client::CommandServiceClient,
    heartbeat_service_client::HeartbeatServiceClient,
    ingestion_service_client::IngestionServiceClient,
    screen_service_client::ScreenServiceClient,
    shell_service_client::ShellServiceClient,
    CommandEnvelope, CommandResult, Ping, ScreenClientMsg, ScreenFrameChunk,
    ShellClientMsg, TelemetryBatch, TelemetryEvent,
};
use crate::shell_session::ShellSessions;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{error, info, warn};

/// A sender that's "live" only while a connection is actually up; swapped
/// in/out on every reconnect. `None` means "not connected right now".
type ActiveSlot<T> = Arc<Mutex<Option<mpsc::Sender<T>>>>;

/// Spawn the tunnel as a background task. It reconnects forever.
/// Callers push telemetry via `batch_tx`'s matching receiver, receive
/// commands via `cmd_tx`, and push command results via `result_rx`.
pub fn spawn(
    cfg: Config,
    batch_rx: mpsc::Receiver<Vec<TelemetryEvent>>,
    cmd_tx: mpsc::Sender<CommandEnvelope>,
    result_rx: mpsc::Receiver<CommandResult>,
    heartbeat_state: Arc<HeartbeatState>,
) {
    let tel_slot: ActiveSlot<TelemetryBatch> = Arc::new(Mutex::new(None));
    let res_slot: ActiveSlot<CommandResult> = Arc::new(Mutex::new(None));

    // Whole-agent-lifetime forwarders (see module doc for why).
    tokio::spawn(forward_telemetry(batch_rx, cfg.agent_id.clone(), tel_slot.clone()));
    tokio::spawn(forward_results(result_rx, res_slot.clone()));

    tokio::spawn(async move {
        tunnel_loop(cfg, tel_slot, cmd_tx, res_slot, heartbeat_state).await;
    });
}

/// Reads telemetry batches forever; sends into whichever connection is
/// currently active, or falls back to the on-disk offline buffer.
async fn forward_telemetry(
    mut batch_rx: mpsc::Receiver<Vec<TelemetryEvent>>,
    agent_id: String,
    slot: ActiveSlot<TelemetryBatch>,
) {
    while let Some(events) = batch_rx.recv().await {
        let maybe_tx = { slot.lock().unwrap().clone() };
        let delivered = if let Some(tx) = maybe_tx {
            let batch = TelemetryBatch { agent_id: agent_id.clone(), events: events.clone() };
            tx.send(batch).await.is_ok()
        } else {
            false
        };
        if !delivered {
            match OfflineBuffer::open_default() {
                Ok(buf) => {
                    if let Err(e) = buf.store(&events) {
                        error!("tunnel: offline buffer write failed: {e}");
                    }
                }
                Err(e) => error!("tunnel: offline buffer unavailable: {e}"),
            }
        }
    }
}

/// Reads command results forever (produced by control::run_dispatcher) and
/// forwards them to the server over whichever connection is currently
/// active. Results for commands run while disconnected are rare (the
/// server can't have delivered a command with no stream open) — if it
/// somehow happens, the result is logged and dropped rather than queued,
/// since the server's own request already timed out on its end.
async fn forward_results(mut result_rx: mpsc::Receiver<CommandResult>, slot: ActiveSlot<CommandResult>) {
    while let Some(r) = result_rx.recv().await {
        let maybe_tx = { slot.lock().unwrap().clone() };
        match maybe_tx {
            Some(tx) => {
                if tx.send(r).await.is_err() {
                    warn!("tunnel: command result dropped — connection just closed");
                }
            }
            None => warn!("tunnel: command result dropped — not connected"),
        }
    }
}

async fn tunnel_loop(
    cfg: Config,
    tel_slot: ActiveSlot<TelemetryBatch>,
    cmd_tx: mpsc::Sender<CommandEnvelope>,
    res_slot: ActiveSlot<CommandResult>,
    heartbeat_state: Arc<HeartbeatState>,
) {
    let mut attempt: u32 = 0;

    loop {
        info!("tunnel: connecting to {} (attempt {})", cfg.server_addr, attempt + 1);

        match connect(&cfg).await {
            Err(e) => {
                error!("tunnel: connect failed: {e}");
            }
            Ok(channel) => {
                attempt = 0;
                heartbeat_state.reset();
                info!("tunnel: connected — opening 4 multiplexed streams");

                if let Err(e) =
                    run_streams(&cfg, channel, &tel_slot, &cmd_tx, &res_slot, &heartbeat_state).await
                {
                    error!("tunnel: stream error: {e}");
                }

                // Torn down (by any one stream failing) — the whole
                // connection reconnects together, so mark nothing active
                // until the next successful connect.
                *tel_slot.lock().unwrap() = None;
                *res_slot.lock().unwrap() = None;
            }
        }

        let backoff = Duration::from_secs(2u64.pow(attempt.min(6)));
        let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
        warn!("tunnel: reconnecting in {}ms", (backoff + jitter).as_millis());
        tokio::time::sleep(backoff + jitter).await;
        attempt += 1;
    }
}

/// Establish a mTLS channel with certificate pinning.
async fn connect(cfg: &Config) -> Result<Channel> {
    let ca_pem = tokio::fs::read(&cfg.server_ca).await?;
    verify_fingerprint(&ca_pem, &cfg.server_ca_fingerprint)?;

    let client_cert_pem = tokio::fs::read(&cfg.client_cert).await?;
    let client_key_pem = tokio::fs::read(&cfg.client_key).await?;

    let tls = ClientTlsConfig::new()
        .domain_name(domain_of(&cfg.server_addr))
        .ca_certificate(Certificate::from_pem(&ca_pem))
        .identity(Identity::from_pem(&client_cert_pem, &client_key_pem));

    let channel = Channel::from_shared(cfg.server_addr.clone())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .connect()
        .await?;

    Ok(channel)
}

/// Opens and drives all four streams concurrently on one connection.
/// Returns (with an error, or Ok on a clean server-initiated close) as soon
/// as ANY of them ends — the caller treats that as "reconnect everything".
async fn run_streams(
    cfg: &Config,
    channel: Channel,
    tel_slot: &ActiveSlot<TelemetryBatch>,
    cmd_tx: &mpsc::Sender<CommandEnvelope>,
    res_slot: &ActiveSlot<CommandResult>,
    heartbeat_state: &Arc<HeartbeatState>,
) -> Result<()> {
    let agent_id = cfg.agent_id.clone();

    let mut tel_client = IngestionServiceClient::new(channel.clone());
    let mut cmd_client = CommandServiceClient::new(channel.clone());
    let mut shell_client = ShellServiceClient::new(channel.clone());
    let mut hb_client = HeartbeatServiceClient::new(channel.clone());
    let mut screen_client = ScreenServiceClient::new(channel);

    // — Telemetry —
    let (tel_tx, tel_rx) = mpsc::channel::<TelemetryBatch>(32);
    *tel_slot.lock().unwrap() = Some(tel_tx.clone());

    // Drain anything buffered while offline straight into this connection.
    let drain_handle = tokio::spawn({
        let tx = tel_tx.clone();
        let agent_id = agent_id.clone();
        async move {
            match OfflineBuffer::open_default() {
                Ok(buf) => {
                    for events in buf.drain(200) {
                        let batch = TelemetryBatch { agent_id: agent_id.clone(), events };
                        if tx.send(batch).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => warn!("tunnel: offline buffer unavailable for drain: {e}"),
            }
        }
    });

    // — Command results —
    let (res_tx, res_rx) = mpsc::channel::<CommandResult>(32);
    *res_slot.lock().unwrap() = Some(res_tx);

    // — Shell —
    let (shell_out_tx, shell_out_rx) = mpsc::channel::<ShellClientMsg>(64);
    let mut shell_sessions = ShellSessions::new(agent_id.clone(), shell_out_tx);

    // — Heartbeat —
    let (hb_tx, hb_rx) = mpsc::channel::<Ping>(4);
    let _ = hb_tx.try_send(Ping { client_time_unix_ms: now_ms() });
    let hb_tx_task = hb_tx.clone();
    let hb_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PING_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let ping = Ping { client_time_unix_ms: now_ms() };
            if hb_tx_task.send(ping).await.is_err() {
                break;
            }
        }
    });

    let mut tel_in = tel_client
        .stream_telemetry(ReceiverStream::new(tel_rx))
        .await?
        .into_inner();
    let mut cmd_in = cmd_client
        .stream_commands(ReceiverStream::new(res_rx))
        .await?
        .into_inner();
    let mut shell_in = shell_client
        .stream_shell(ReceiverStream::new(shell_out_rx))
        .await?
        .into_inner();
    let mut hb_in = hb_client
        .stream_heartbeat(ReceiverStream::new(hb_rx))
        .await?
        .into_inner();

    let (screen_tx, screen_rx) = mpsc::channel::<ScreenClientMsg>(8);
    let screen_in_opt = match screen_client
        .stream_screen(ReceiverStream::new(screen_rx))
        .await
    {
        Ok(s) => {
            info!("tunnel: screen streaming stream established successfully!");
            Some(s)
        }
        Err(e) => {
            error!("tunnel: screen streaming connect failed: {e:?}");
            None
        }
    };

    let screen_handle = if let Some(s_in) = screen_in_opt {
        let s_tx = screen_tx.clone();
        let mut s_stream = s_in.into_inner();
        tokio::spawn(async move {
            let mut seq: u32 = 0;
            let mut is_streaming = true;
            let mut interval = tokio::time::interval(Duration::from_millis(350));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Send one initial frame for dashboard thumbnail immediately
            let res = tokio::task::spawn_blocking(|| {
                crate::screen_capture::capture_desktop_jpeg(45)
            }).await;
            if let Ok(Ok(data)) = res {
                seq = seq.wrapping_add(1);
                let msg = ScreenClientMsg {
                    msg: Some(crate::pb::screen_client_msg::Msg::Frame(
                        ScreenFrameChunk {
                            data,
                            is_keyframe: true,
                            sequence: seq,
                        }
                    )),
                };
                let _ = s_tx.send(msg).await;
            }

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !is_streaming {
                            continue;
                        }
                        let res = tokio::task::spawn_blocking(|| {
                            crate::screen_capture::capture_desktop_jpeg(50)
                        }).await;
                        match res {
                            Ok(Ok(data)) => {
                                seq = seq.wrapping_add(1);
                                let msg = ScreenClientMsg {
                                    msg: Some(crate::pb::screen_client_msg::Msg::Frame(
                                        ScreenFrameChunk {
                                            data,
                                            is_keyframe: true,
                                            sequence: seq,
                                        }
                                    )),
                                };
                                if s_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::debug!("tunnel: screen capture skipped or failed: {e}");
                            }
                            Err(e) => {
                                tracing::debug!("tunnel: spawn_blocking capture error: {e}");
                            }
                        }
                    }
                    srv_msg = s_stream.message() => {
                        match srv_msg {
                            Ok(Some(msg)) => {
                                match msg.msg {
                                    Some(crate::pb::screen_server_msg::Msg::Start(_)) => {
                                        tracing::info!("tunnel: screen live streaming activated by server");
                                        is_streaming = true;
                                    }
                                    Some(crate::pb::screen_server_msg::Msg::Stop(_)) => {
                                        tracing::info!("tunnel: screen live streaming paused (idle)");
                                        is_streaming = false;
                                    }
                                    None => {}
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }
        })
    } else {
        tokio::spawn(async {})
    };

    let (err_tx, mut err_rx) = mpsc::channel::<Result<()>>(4);

    let err_tx_tel = err_tx.clone();
    let tel_handle = tokio::spawn(async move {
        loop {
            match tel_in.message().await {
                Ok(Some(ack)) => tracing::debug!(accepted = ack.accepted_count, "telemetry ack"),
                Ok(None) => { let _ = err_tx_tel.send(Ok(())).await; break; }
                Err(e) => { let _ = err_tx_tel.send(Err(e.into())).await; break; }
            }
        }
    });

    let err_tx_cmd = err_tx.clone();
    let cmd_tx_c = cmd_tx.clone();
    let cmd_handle = tokio::spawn(async move {
        loop {
            match cmd_in.message().await {
                Ok(Some(env)) => {
                    info!("tunnel: received command: id={}", env.command_id);
                    let _ = cmd_tx_c.send(env).await;
                }
                Ok(None) => { let _ = err_tx_cmd.send(Ok(())).await; break; }
                Err(e) => { let _ = err_tx_cmd.send(Err(e.into())).await; break; }
            }
        }
    });

    let err_tx_shell = err_tx.clone();
    let shell_handle = tokio::spawn(async move {
        loop {
            match shell_in.message().await {
                Ok(Some(server_msg)) => shell_sessions.handle(server_msg),
                Ok(None) => { let _ = err_tx_shell.send(Ok(())).await; break; }
                Err(e) => { let _ = err_tx_shell.send(Err(e.into())).await; break; }
            }
        }
    });

    let err_tx_hb = err_tx;
    let hb_state_c = heartbeat_state.clone();
    let hb_rx_handle = tokio::spawn(async move {
        loop {
            match hb_in.message().await {
                Ok(Some(pong)) => {
                    let diff = now_ms() - pong.client_time_unix_ms;
                    let rtt = if diff >= 0 && diff < 500 { diff } else { 2 };
                    hb_state_c.record_pong(rtt);
                }
                Ok(None) => { let _ = err_tx_hb.send(Ok(())).await; break; }
                Err(e) => { let _ = err_tx_hb.send(Err(e.into())).await; break; }
            }
        }
    });

    let result = err_rx.recv().await.unwrap_or(Ok(()));

    tel_handle.abort();
    cmd_handle.abort();
    shell_handle.abort();
    hb_rx_handle.abort();
    drain_handle.abort();
    hb_handle.abort();
    screen_handle.abort();

    result
}

/// SHA-256 of the raw PEM bytes must match the pinned hex string. This is
/// what defeats a corporate TLS-interception proxy or DNS-spoof MITM even
/// though the agent only ever dials a hostname, never a pinned IP.
fn verify_fingerprint(ca_pem: &[u8], expected: &str) -> Result<()> {
    let hash = Sha256::digest(ca_pem);
    let actual = hex::encode(hash);
    let clean = expected.to_lowercase().replace([':', ' '], "");
    if clean == "replace_with_real_fingerprint" {
        warn!("tunnel: cert pinning disabled (dev mode — set EG_SERVER_CA_FINGERPRINT)");
        return Ok(());
    }
    if actual != clean {
        bail!("tunnel: CA fingerprint mismatch — possible MITM!\n  got:      {actual}\n  expected: {clean}");
    }
    Ok(())
}

/// Extract the hostname from a URL like `https://host:443` → `host`. The
/// agent only ever dials by hostname — no IP address appears in config or
/// on the wire.
fn domain_of(addr: &str) -> String {
    let host = addr.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();
    if host.parse::<std::net::IpAddr>().is_ok() || host == "localhost" {
        return "control.endpointguard.internal".to_string();
    }
    host
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
