pub mod dlp;
pub mod network;
pub mod process_etw;
pub mod system;
pub mod window;

use crate::pb::TelemetryEvent;
use tokio::sync::mpsc::Sender;

/// Starts every collector as an independent async task + one dedicated
/// OS thread for ETW (which blocks its calling thread via ProcessTrace).
pub fn spawn_all(tx: Sender<TelemetryEvent>, agent_id: String) {
    tokio::spawn(process_etw::run(tx.clone(), agent_id.clone()));
    tokio::spawn(window::run(tx.clone(), agent_id.clone()));
    tokio::spawn(system::run(tx.clone(), agent_id.clone()));
    tokio::spawn(network::run(tx.clone(), agent_id.clone()));
    tokio::spawn(dlp::run(tx, agent_id));
}

pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub(crate) fn hostname() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::{
            ComputerNamePhysicalDnsHostname, GetComputerNameExW,
        };
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        unsafe {
            let _ = GetComputerNameExW(
                ComputerNamePhysicalDnsHostname,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            );
        }
        String::from_utf16_lossy(&buf[..len as usize])
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".into())
    }
}
