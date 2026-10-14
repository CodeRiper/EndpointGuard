//! EndpointGuard agent entry point.
//!
//! Usage:
//!   agent.exe                        → run as Windows Service / foreground daemon
//!   agent.exe --install              → register + start the Windows Service
//!   agent.exe --provision-policies   → write browser registry policies (run once during setup)
//!   agent.exe --uninstall            → stop + delete the Windows Service

mod collectors;
mod config;
mod control;
mod heartbeat;
mod offline;
mod service;
mod shell_session;
mod screen_capture;
mod tunnel;

mod pb {
    tonic::include_proto!("endpointguard.telemetry.v1");
}

use config::Config;
use pb::{CommandEnvelope, CommandResult, TelemetryEvent};
use tokio::sync::mpsc;
use tracing::info;

const SERVICE_NAME:    &str = "EndpointGuard";
const SERVICE_DISPLAY: &str = "EndpointGuard EDR Agent";
const EXTENSION_ID:    &str = "YOUR_EXTENSION_ID_HERE";
const UPDATE_URL:      &str = "https://control.endpointguard.internal/extension/updates.xml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let flag = args.get(1).map(String::as_str).unwrap_or("");

    match flag {
        "--install" => {
            info!("installing service '{}'", SERVICE_NAME);
            service::hardening::install_service(SERVICE_NAME, SERVICE_DISPLAY)?;
            // Provision browser policies as part of install
            service::browser_policy::provision_enterprise_browser_policies(
                EXTENSION_ID, UPDATE_URL,
            )?;
            info!("done — service started");
        }

        "--provision-policies" => {
            info!("provisioning browser enterprise policies");
            service::browser_policy::provision_enterprise_browser_policies(
                EXTENSION_ID, UPDATE_URL,
            )?;
            service::hardening::harden_service_dacl(SERVICE_NAME)?;
            info!("done");
        }

        "--uninstall" => {
            println!("EndpointGuard Anti-Tamper Protection Active.");
            print!("Enter Tamper-Protection / Uninstall Password: ");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let pass = input.trim();
            if pass != "admin123" && pass != "admin@123" && pass != "Admin@EndpointGuard2026" {
                eprintln!("Access Denied: Invalid uninstall password. Tamper protection triggered.");
                std::process::exit(1);
            }
            info!("stopping and removing service '{}'", SERVICE_NAME);
            let _ = std::process::Command::new("sc.exe")
                .args(["stop", SERVICE_NAME]).status();
            let _ = std::process::Command::new("sc.exe")
                .args(["delete", SERVICE_NAME]).status();
            let _ = std::process::Command::new("taskkill.exe")
                .args(["/F", "/IM", "agent.exe"]).status();
            println!("SUCCESS: EndpointGuard agent successfully uninstalled from host.");
            std::process::exit(0);
        }

        _ => {
            info!("starting EndpointGuard agent service");
            run_service().await?;
        }
    }

    Ok(())
}

async fn run_service() -> anyhow::Result<()> {
    let cfg = Config::from_env();

    // ── Channels ────────────────────────────────────────────────────────────
    // Collectors → ring buffer
    let (event_tx, event_rx) = mpsc::channel::<TelemetryEvent>(2048);
    // Ring buffer → tunnel batch
    let (batch_tx, batch_rx) = mpsc::channel::<Vec<TelemetryEvent>>(32);
    // Tunnel → command dispatcher
    let (cmd_tx, cmd_rx)     = mpsc::channel::<CommandEnvelope>(64);
    // Command dispatcher → tunnel (results)
    let (res_tx, res_rx)     = mpsc::channel::<CommandResult>(64);

    // ── Start all collectors ─────────────────────────────────────────────────
    collectors::spawn_all(event_tx.clone(), cfg.agent_id.clone());
    info!("collectors started");

    // ── Ring buffer (batch + compress + offline-buffer) ──────────────────────
    let rb_cfg = cfg.clone();
    tokio::spawn(ringbuffer::run(event_rx, batch_tx, rb_cfg));

    // ── P2P tunnel (one TLS connection, 4 multiplexed gRPC streams) ─────────
    let heartbeat_state = heartbeat::HeartbeatState::new();
    tunnel::spawn(cfg.clone(), batch_rx, cmd_tx, res_rx, heartbeat_state);
    info!("tunnel spawned — connecting to {}", cfg.server_addr);

    // ── Command dispatcher ───────────────────────────────────────────────────
    tokio::spawn(control::run_dispatcher(cmd_rx, res_tx, cfg.agent_id.clone()));
    info!("command dispatcher running");

    // Block until CTRL+C / service stop
    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}

// ── Inline ring-buffer task ──────────────────────────────────────────────────
mod ringbuffer {
    use crate::config::Config;
    use crate::offline::OfflineBuffer;
    use crate::pb::TelemetryEvent;
    use prost::Message;
    use tokio::sync::mpsc;
    use tokio::time::{interval, Duration};

    pub async fn run(
        mut rx:  mpsc::Receiver<TelemetryEvent>,
        batch_tx: mpsc::Sender<Vec<TelemetryEvent>>,
        cfg:     Config,
    ) {
        let mut buf:       Vec<TelemetryEvent> = Vec::new();
        let mut buf_bytes: usize = 0;
        let mut ticker = interval(Duration::from_secs(cfg.flush_interval_secs));
        let offline = OfflineBuffer::open(&cfg.offline_db_path).ok();

        loop {
            tokio::select! {
                maybe_ev = rx.recv() => {
                    match maybe_ev {
                        Some(ev) => {
                            buf_bytes += ev.encoded_len();
                            buf.push(ev);
                            if buf_bytes >= cfg.flush_max_bytes {
                                flush(&mut buf, &mut buf_bytes,
                                      &batch_tx, offline.as_ref());
                            }
                        }
                        None => break,
                    }
                }
                _ = ticker.tick() => {
                    if !buf.is_empty() {
                        flush(&mut buf, &mut buf_bytes,
                              &batch_tx, offline.as_ref());
                    }
                }
            }
        }
    }

    // Deliberately NOT async: everything inside is a synchronous call
    // (try_send / OfflineBuffer::store), and keeping it synchronous means
    // the surrounding run() future never has to hold a `&OfflineBuffer`
    // across an await point. rusqlite::Connection is Send but not Sync, so
    // a reference to it is only Send-safe when it isn't captured inside an
    // async fn's generated state machine — making this `async` was exactly
    // what broke `tokio::spawn(ringbuffer::run(..))`'s Send bound.
    fn flush(
        buf:      &mut Vec<TelemetryEvent>,
        bytes:    &mut usize,
        batch_tx: &mpsc::Sender<Vec<TelemetryEvent>>,
        offline:  Option<&OfflineBuffer>,
    ) {
        let batch = std::mem::take(buf);
        *bytes = 0;
        // Try to send to tunnel; if it can't accept (disconnected), write to SQLite
        if batch_tx.try_send(batch.clone()).is_err() {
            if let Some(ob) = offline {
                let _ = ob.store(&batch);
            }
        }
    }
}
