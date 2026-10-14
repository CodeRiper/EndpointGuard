//! SQLite ring-buffer for offline event storage.
//!
//! When the tunnel is down, collected events are written here instead
//! of being dropped.  On reconnect, `drain()` paginates them out and
//! deletes as it goes.  The table is capped at ~500 MB by a TTL delete
//! that runs on every insert batch.

use crate::pb::TelemetryEvent;
use anyhow::Result;
use prost::Message;
use rusqlite::{params, Connection};

const MAX_ROWS: i64 = 500_000; // ~500 MB at ~1 KB/row average

pub struct OfflineBuffer {
    conn: Connection,
}

impl OfflineBuffer {
    pub fn open_default() -> Result<Self> {
        let path = std::env::var("EG_OFFLINE_DB")
            .unwrap_or_else(|_| "/tmp/eg_cache.db".into());
        Self::open(&path)
    }

    pub fn open(path: &str) -> Result<Self> {
        // Create parent dir if it doesn't exist
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                ts    INTEGER NOT NULL,
                data  BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ts ON events(ts);
        ")?;
        Ok(Self { conn })
    }

    /// Persist a batch of events (protobuf-encoded, then stored individually).
    pub fn store(&self, events: &[TelemetryEvent]) -> Result<()> {
        let ts = chrono::Utc::now().timestamp_millis();
        let tx = self.conn.unchecked_transaction()?;
        for ev in events {
            let mut buf = Vec::with_capacity(ev.encoded_len());
            ev.encode(&mut buf)?;
            tx.execute("INSERT INTO events (ts, data) VALUES (?1, ?2)", params![ts, buf])?;
        }
        tx.commit()?;
        // Evict oldest rows if over cap
        self.conn.execute(
            "DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY rowid ASC LIMIT MAX(0, (SELECT COUNT(*) FROM events) - ?1))",
            params![MAX_ROWS],
        )?;
        Ok(())
    }

    /// Drain up to `page_size` events, delete them, return as Vec<Event>.
    pub fn drain(&self, page_size: usize) -> Vec<Vec<TelemetryEvent>> {
        let mut result = Vec::new();
        loop {
            let rows: Vec<(i64, Vec<u8>)> = self.conn.prepare(
                "SELECT rowid, data FROM events ORDER BY rowid ASC LIMIT ?1"
            )
            .and_then(|mut stmt| {
                stmt.query_map(params![page_size as i64], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .and_then(|rows| rows.collect())
            })
            .unwrap_or_default();

            if rows.is_empty() { break; }

            let max_rowid = rows.last().map(|(id, _)| *id).unwrap_or(0);
            let events: Vec<TelemetryEvent> = rows.into_iter()
                .filter_map(|(_, data)| TelemetryEvent::decode(data.as_slice()).ok())
                .collect();

            let _ = self.conn.execute(
                "DELETE FROM events WHERE rowid <= ?1", params![max_rowid],
            );

            if !events.is_empty() {
                result.push(events);
            }
        }
        result
    }
}
