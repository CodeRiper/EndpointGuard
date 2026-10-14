use crate::config::Config;
use crate::pb::ingestion_service_client::IngestionServiceClient;
use crate::pb::{TelemetryBatch, TelemetryEvent};
use anyhow::Result;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

/// Dials the server with hardware-bound mTLS: the agent presents its
/// own client cert/key and pins the server CA, matching the
/// blueprint's outbound-initiated TLS 1.3 reverse tunnel.
pub async fn connect(cfg: &Config) -> Result<IngestionServiceClient<Channel>> {
    let client_cert = tokio::fs::read(&cfg.client_cert).await?;
    let client_key = tokio::fs::read(&cfg.client_key).await?;
    let server_ca = tokio::fs::read(&cfg.server_ca).await?;

    let tls = ClientTlsConfig::new()
        .domain_name(domain_of(&cfg.server_addr))
        .ca_certificate(Certificate::from_pem(server_ca))
        .identity(Identity::from_pem(client_cert, client_key));

    let channel = Channel::from_shared(cfg.server_addr.clone())?
        .tls_config(tls)?
        .connect()
        .await?;

    Ok(IngestionServiceClient::new(channel))
}

/// Opens the one long-lived bidirectional stream: batches arriving
/// on `batch_rx` go out to the server; acks come back and are
/// logged (nothing acts on them yet — a natural hook for retry/
/// backpressure logic later).
pub async fn run_stream(
    mut client: IngestionServiceClient<Channel>,
    agent_id: String,
    mut batch_rx: mpsc::Receiver<Vec<TelemetryEvent>>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<TelemetryBatch>(32);

    tokio::spawn(async move {
        while let Some(events) = batch_rx.recv().await {
            let batch = TelemetryBatch {
                agent_id: agent_id.clone(),
                events,
            };
            if tx.send(batch).await.is_err() {
                break;
            }
        }
    });

    let outbound = ReceiverStream::new(rx);
    let response = client.stream_telemetry(outbound).await?;
    let mut inbound = response.into_inner();

    while let Some(ack) = inbound.message().await? {
        tracing::debug!(accepted = ack.accepted_count, "server ack");
    }
    Ok(())
}

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
