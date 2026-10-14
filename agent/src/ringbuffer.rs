use crate::pb::TelemetryEvent;
use prost::Message;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

/// Collects events from every collector and flushes a batch on
/// whichever comes first: `flush_interval` elapses, or the buffered
/// payload would exceed `flush_max_bytes` — the blueprint's
/// "10 seconds or 64 KB" ring-buffer policy.
pub struct RingBuffer {
    rx: mpsc::Receiver<TelemetryEvent>,
    flush_interval: Duration,
    flush_max_bytes: usize,
}

impl RingBuffer {
    pub fn new(
        rx: mpsc::Receiver<TelemetryEvent>,
        flush_interval_secs: u64,
        flush_max_bytes: usize,
    ) -> Self {
        Self {
            rx,
            flush_interval: Duration::from_secs(flush_interval_secs),
            flush_max_bytes,
        }
    }

    /// Runs until every collector's sender half is dropped, calling
    /// `on_flush` once per completed batch.
    pub async fn run<F, Fut>(mut self, on_flush: F)
    where
        F: Fn(Vec<TelemetryEvent>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut buf: Vec<TelemetryEvent> = Vec::new();
        let mut buf_bytes = 0usize;
        let mut ticker = interval(self.flush_interval);

        loop {
            tokio::select! {
                maybe_ev = self.rx.recv() => {
                    match maybe_ev {
                        Some(ev) => {
                            buf_bytes += ev.encoded_len();
                            buf.push(ev);
                            if buf_bytes >= self.flush_max_bytes {
                                on_flush(std::mem::take(&mut buf)).await;
                                buf_bytes = 0;
                            }
                        }
                        None => break,
                    }
                }
                _ = ticker.tick() => {
                    if !buf.is_empty() {
                        on_flush(std::mem::take(&mut buf)).await;
                        buf_bytes = 0;
                    }
                }
            }
        }
    }
}
