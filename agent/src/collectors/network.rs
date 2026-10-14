use crate::collectors::{hostname, now_ms};
use crate::pb::{
    telemetry_event::Payload, EventType, SocketEntry, SocketSnapshotEvent, TelemetryEvent,
};
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

const POLL_SECS: u64 = 10; // socket-to-PID mapping every 10s (reduced CPU overhead)

pub async fn run(tx: Sender<TelemetryEvent>, agent_id: String) {
    loop {
        let sockets = snapshot();
        if !sockets.is_empty() {
            let ev = TelemetryEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                agent_id: agent_id.clone(),
                hostname: hostname(),
                timestamp_unix_ms: now_ms(),
                event_type: EventType::SocketSnapshot as i32,
                payload: Some(Payload::SocketSnapshot(SocketSnapshotEvent {
                    sockets,
                    captured_time_unix_ms: now_ms(),
                })),
            };
            if tx.send(ev).await.is_err() {
                return;
            }
        }
        sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

// GetExtendedTcpTable's two-call sizing pattern, as the blueprint
// describes it. The MIB_TCPROW_OWNER_PID field names below match
// the Win32 struct; windows-rs's exact Rust field casing/types can
// drift between crate versions, so check this against the installed
// 0.56.x docs before trusting it blind.
#[cfg(windows)]
fn snapshot() -> Vec<SocketEntry> {
    use std::net::Ipv4Addr;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    unsafe {
        let mut size: u32 = 0;
        // First call sizes the buffer.
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return Vec::new();
        }

        let mut buf = vec![0u8; size as usize];
        let ptr = buf.as_mut_ptr() as *mut core::ffi::c_void;
        let res = GetExtendedTcpTable(
            Some(ptr),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if res != NO_ERROR.0 {
            return Vec::new();
        }

        let table = &*(ptr as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);

        rows.iter()
            .map(|row| SocketEntry {
                local_addr: Ipv4Addr::from(row.dwLocalAddr.to_be()).to_string(),
                local_port: u16::from_be((row.dwLocalPort & 0xFFFF) as u16) as u32,
                remote_addr: Ipv4Addr::from(row.dwRemoteAddr.to_be()).to_string(),
                remote_port: u16::from_be((row.dwRemotePort & 0xFFFF) as u16) as u32,
                state: tcp_state_name(row.dwState),
                owning_pid: row.dwOwningPid,
                protocol: "TCP".into(),
            })
            .collect()
    }
}

#[cfg(windows)]
fn tcp_state_name(state: u32) -> String {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
    .to_string()
}

#[cfg(not(windows))]
fn snapshot() -> Vec<SocketEntry> {
    Vec::new()
}
