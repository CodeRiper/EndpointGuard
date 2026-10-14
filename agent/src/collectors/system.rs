use crate::collectors::{hostname, now_ms};
use crate::pb::{telemetry_event::Payload, EventType, SystemMetricEvent, TelemetryEvent};
use sysinfo::{Disks, System};
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

// 15 s is plenty for system metrics — CPU/RAM don't change meaningfully
// faster than this, and the old 5 s interval was tripling our sysinfo
// overhead for no actionable benefit.
const POLL_SECS: u64 = 15;
// Refresh disk stats every Nth poll (~90 s). Disk I/O enumeration is
// surprisingly heavy on Windows (WMI under the hood).
const DISK_REFRESH_EVERY: u32 = 6;

pub async fn run(tx: Sender<TelemetryEvent>, agent_id: String) {
    // System::new() only allocates the struct — no full process/network
    // enumeration unlike new_all(), which was the #1 startup CPU spike.
    let mut sys = System::new();
    let mut disks = Disks::new_with_refreshed_list();
    let mut disk_used_bytes: u64 = 0;
    let mut disk_total_bytes: u64 = 0;
    let mut tick_count: u32 = 0;

    // Pre-compute initial disk stats.
    if let Some(d) = disks.list().first() {
        disk_total_bytes = d.total_space();
        disk_used_bytes = disk_total_bytes.saturating_sub(d.available_space());
    }

    loop {
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        // Only re-enumerate disks periodically.
        tick_count += 1;
        if tick_count % DISK_REFRESH_EVERY == 0 {
            disks = Disks::new_with_refreshed_list();
            if let Some(d) = disks.list().first() {
                disk_total_bytes = d.total_space();
                disk_used_bytes = disk_total_bytes.saturating_sub(d.available_space());
            }
        }

        let cpu_usage_percent = sys.global_cpu_info().cpu_usage() as f64;
        let memory_used_bytes = sys.used_memory();
        let memory_total_bytes = sys.total_memory();
        let (battery_percent, is_ac_connected) = power_status();

        let ev = TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.clone(),
            hostname: hostname(),
            timestamp_unix_ms: now_ms(),
            event_type: EventType::SystemMetric as i32,
            payload: Some(Payload::Metric(SystemMetricEvent {
                cpu_usage_percent,
                memory_used_bytes,
                memory_total_bytes,
                disk_used_bytes,
                disk_total_bytes,
                battery_percent,
                is_ac_connected,
                // Rolled up from the window collector's idle math in
                // a later pass — zeroed for now rather than guessed.
                screen_on_time_total_s: 0,
                active_dwell_time_s: 0,
                idle_time_s: 0,
            })),
        };
        if tx.send(ev).await.is_err() {
            return;
        }
        sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

#[cfg(windows)]
fn power_status() -> (f32, bool) {
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut status = SYSTEM_POWER_STATUS::default();
    unsafe {
        if GetSystemPowerStatus(&mut status).is_ok() {
            let pct = if status.BatteryLifePercent == 255 {
                100.0
            } else {
                status.BatteryLifePercent as f32
            };
            return (pct, status.ACLineStatus == 1);
        }
    }
    (100.0, true)
}

#[cfg(not(windows))]
fn power_status() -> (f32, bool) {
    (100.0, true)
}
