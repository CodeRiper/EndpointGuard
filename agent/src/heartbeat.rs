//! Dedicated low-latency liveness channel.
//!
//! This is its own gRPC service/stream (see proto `HeartbeatService`) so a
//! slow telemetry upload or a busy shell session can never delay dead-
//! connection detection: the agent pings the server every `PING_INTERVAL`
//! and the server echoes it straight back, letting both sides measure RTT
//! and notice a stuck/half-open connection fast.
//!
//! `HeartbeatState` is lock-free (`AtomicI64`) so collectors or a future
//! status UI can read the last-seen time / RTT without contending with the
//! tunnel's hot path.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Ping the server this often. Independent of the telemetry flush interval
/// and of any command/shell traffic — that's the whole point of splitting
/// this into its own service.
pub const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// An agent counts its own link as stale if it hasn't heard a Pong in this
/// long (a couple of missed beats' worth of tolerance).
const STALE_AFTER_MS: i64 = 6_000;

/// RTTs above this are logged as a warning — not fatal, just worth knowing
/// about when diagnosing "feels slow" reports.
const SLOW_RTT_WARN_MS: i64 = 1_000;

pub struct HeartbeatState {
    last_pong_unix_ms: AtomicI64,
    rtt_ms: AtomicI64,
}

impl HeartbeatState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            last_pong_unix_ms: AtomicI64::new(0),
            rtt_ms: AtomicI64::new(0),
        })
    }

    pub fn record_pong(&self, rtt_ms: i64) {
        self.last_pong_unix_ms.store(now_ms(), Ordering::Relaxed);
        self.rtt_ms.store(rtt_ms.max(0), Ordering::Relaxed);
        if rtt_ms > SLOW_RTT_WARN_MS {
            tracing::warn!("heartbeat: slow RTT {}ms", rtt_ms);
        }
    }

    /// True once we've never heard a pong yet, or it's been too long since
    /// the last one — i.e. the connection should be treated as dead even if
    /// the TCP socket hasn't noticed yet.
    pub fn is_stale(&self) -> bool {
        let last = self.last_pong_unix_ms.load(Ordering::Relaxed);
        last == 0 || now_ms() - last > STALE_AFTER_MS
    }

    pub fn rtt_ms(&self) -> i64 {
        self.rtt_ms.load(Ordering::Relaxed)
    }

    /// Called on every reconnect attempt so a stale reading from a previous
    /// (now-dead) connection doesn't look "fresh" during the gap.
    pub fn reset(&self) {
        self.last_pong_unix_ms.store(0, Ordering::Relaxed);
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
