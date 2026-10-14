//! ETW process-start / process-stop collector.
//!
//! Subscribes to Microsoft-Windows-Kernel-Process
//! GUID {22FB2CD6-0E7B-4E8F-9D10-4A8A7C0C0F2F}
//!   Event ID 1 → Process Start
//!   Event ID 2 → Process Stop
//!
//! ProcessTrace() blocks its calling thread forever, so this module
//! runs on a dedicated OS thread (not a Tokio task).  Events cross
//! into the async world through a bounded sync channel.

use crate::collectors::{hostname, now_ms};
use crate::pb::{telemetry_event::Payload, EventType, ProcessEvent, TelemetryEvent};
use std::sync::OnceLock;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;


/// Starts the ETW listener thread and feeds events into `tx`.
pub async fn run(tx: Sender<TelemetryEvent>, agent_id: String) {
    // Bridge: OS-thread sync_sender → async mpsc::Sender
    let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel::<ProcessRecord>(512);
    let _ = ETW_ASYNC_TX.set(sync_tx);

    // Spawn the dedicated OS thread for ProcessTrace (it blocks)
    std::thread::spawn(move || {
        #[cfg(windows)]
        win::etw_thread_main();
        #[cfg(not(windows))]
        { tracing::warn!("ETW collector: Windows only"); }
    });

    while let Some(rec) = sync_rx.recv().await {
        let (event_type, payload) = match rec.event_id {
            1 => (EventType::ProcessStart, Payload::Process(ProcessEvent {
                process_id:        rec.process_id,
                parent_process_id: rec.parent_process_id,
                image_file_path:   rec.image_file_path.clone(),
                command_line:      rec.command_line.clone(),
                user_sid:          rec.user_sid.clone(),
                user_name:         rec.user_name.clone(),
                session_id:        rec.session_id,
                start_time_unix_ms: now_ms(),
                exit_time_unix_ms:  0,
                exit_code:          0,
                integrity_level:    rec.integrity_level.clone(),
            })),
            2 => (EventType::ProcessStop, Payload::Process(ProcessEvent {
                process_id:        rec.process_id,
                parent_process_id: 0,
                image_file_path:   rec.image_file_path.clone(),
                command_line:      String::new(),
                user_sid:          String::new(),
                user_name:         String::new(),
                session_id:        0,
                start_time_unix_ms: 0,
                exit_time_unix_ms:  now_ms(),
                exit_code:         rec.exit_code,
                integrity_level:   String::new(),
            })),
            _ => continue,
        };

        let ev = TelemetryEvent {
            event_id:         Uuid::new_v4().to_string(),
            agent_id:         agent_id.clone(),
            hostname:         hostname(),
            timestamp_unix_ms: now_ms(),
            event_type:       event_type as i32,
            payload:          Some(payload),
        };
        if tx.send(ev).await.is_err() { break; }
    }
}

// ─── Shared state between ETW callback and async world ───────────────────────

struct ProcessRecord {
    event_id:         u16,
    process_id:       u32,
    parent_process_id:u32,
    image_file_path:  String,
    command_line:     String,
    user_sid:         String,
    user_name:        String,
    session_id:       u32,
    exit_code:        i32,
    integrity_level:  String,
}

// OnceLock<Sender> lets the extern-C callback push into the async world
static ETW_ASYNC_TX: OnceLock<tokio::sync::mpsc::Sender<ProcessRecord>> = OnceLock::new();

// ─── Windows-only ETW implementation ─────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::*;
    
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, EnableTraceEx2, OpenTraceW, ProcessTrace,
        StartTraceW, StopTraceW, EVENT_RECORD,
        EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        WNODE_FLAG_TRACED_GUID,
        TdhGetEventInformation, TdhGetProperty,
        TRACE_EVENT_INFO, PROPERTY_DATA_DESCRIPTOR,
    };
    use windows::Win32::Foundation::ERROR_SUCCESS;

    const SESSION_NAME: &str = "EndpointGuard-KernelProcess\0";
    const PROVIDER_GUID: GUID = GUID {
        data1: 0x22FB2CD6,
        data2: 0x0E7B,
        data3: 0x4E8F,
        data4: [0x9D, 0x10, 0x4A, 0x8A, 0x7C, 0x0C, 0x0F, 0x2F],
    };

    pub fn etw_thread_main() {
        unsafe {
            // ── 1. Allocate EVENT_TRACE_PROPERTIES buffer ──────────────────
            // The struct must be followed immediately by the session-name
            // string in the same allocation (well-known ETW quirk).
            let name_bytes: Vec<u16> = SESSION_NAME.encode_utf16().collect();
            let name_size  = name_bytes.len() * 2 + 2;
            let base_size  = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let total_size = base_size + name_size;

            let mut buf = vec![0u8; total_size];
            let props   = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*props).Wnode.BufferSize   = total_size as u32;
            (*props).Wnode.Flags        = WNODE_FLAG_TRACED_GUID;
            (*props).LogFileMode        = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset   = base_size as u32;
            (*props).EnableFlags        = EVENT_TRACE_FLAG_PROCESS;

            // Copy session name after the struct
            let name_dst = buf.as_mut_ptr().add(base_size) as *mut u16;
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_dst, name_bytes.len());

            // ── 2. Start the trace session ─────────────────────────────────
            let session_name_wide: Vec<u16> = SESSION_NAME.encode_utf16().collect();
            let mut session_handle = windows::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE::default();

            let rc = StartTraceW(&mut session_handle, PCWSTR(session_name_wide.as_ptr()), props);
            if rc != ERROR_SUCCESS {
                tracing::warn!("StartTraceW unavailable ({:?}) — activating user-mode process poller", rc);
                user_mode_process_poller();
                return;
            }

            // ── 3. Enable the kernel-process provider ──────────────────────
            let rc2 = EnableTraceEx2(
                session_handle,
                &PROVIDER_GUID,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                4, // TRACE_LEVEL_INFORMATION
                0, 0, 0,
                None,
            );
            if rc2 != ERROR_SUCCESS {
                tracing::error!("EnableTraceEx2 failed: {:?}", rc2);
                let _ = StopTraceW(session_handle, PCWSTR::null(), props);
                return;
            }

            // ── 4. Open the trace for real-time processing ─────────────────
            let mut log = EVENT_TRACE_LOGFILEW::default();
            log.LoggerName = PWSTR(session_name_wide.as_ptr() as *mut u16);
            log.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log.Anonymous2.EventRecordCallback = Some(event_record_callback);

            let trace_handle = OpenTraceW(&mut log);
            if trace_handle.Value == u64::MAX {
                tracing::error!("OpenTraceW failed");
                let _ = StopTraceW(session_handle, PCWSTR::null(), props);
                return;
            }

            tracing::info!("ETW kernel-process trace started");

            // ── 5. ProcessTrace — blocks until the session is stopped ──────
            let _ = ProcessTrace(&[trace_handle], None, None);
            CloseTrace(trace_handle);
            let _ = StopTraceW(session_handle, PCWSTR::null(), props);
        }
    }

    /// ETW event callback: called by ProcessTrace for every event.
    /// Must be `extern "system"` for the Win32 callback ABI.
    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        if record.is_null() { return; }
        let rec = &*record;

        // Only handle Event IDs 1 (start) and 2 (stop)
        let event_id = rec.EventHeader.EventDescriptor.Id;
        if event_id != 1 && event_id != 2 { return; }

        // ── TDH property extraction ────────────────────────────────────────
        // First call: get the size of TRACE_EVENT_INFO
        let mut info_size: u32 = 0;
        let _ = TdhGetEventInformation(rec, None, None, &mut info_size);
        if info_size == 0 { return; }

        let mut info_buf = vec![0u8; info_size as usize];
        let info_ptr = info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
        if TdhGetEventInformation(rec, None, Some(info_ptr), &mut info_size) != ERROR_SUCCESS.0 {
            return;
        }

        // Helper: extract a named property as UTF-16 string
        let get_str = |name: &str| -> String {
            let wide_name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let desc = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: wide_name.as_ptr() as u64,
                ArrayIndex: 0xFFFFFFFF,
                ..Default::default()
            };

            let mut val_buf = vec![0u8; 512];
            if TdhGetProperty(rec, None, &[desc], &mut val_buf) != ERROR_SUCCESS.0 {
                return String::new();
            }

            // Result is UTF-16 for string properties
            let words: &[u16] = std::slice::from_raw_parts(
                val_buf.as_ptr() as *const u16,
                val_buf.len() / 2,
            );
            let end = words.iter().position(|&c| c == 0).unwrap_or(words.len());
            String::from_utf16_lossy(&words[..end])
        };

        let get_u32 = |name: &str| -> u32 {
            let wide_name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let desc = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: wide_name.as_ptr() as u64,
                ArrayIndex: 0xFFFFFFFF,
                ..Default::default()
            };
            let mut val_buf = [0u8; 4];
            if TdhGetProperty(rec, None, &[desc], &mut val_buf) != ERROR_SUCCESS.0 {
                return 0;
            }
            u32::from_ne_bytes(val_buf)
        };

        let process_rec = ProcessRecord {
            event_id,
            process_id:        get_u32("ProcessID"),
            parent_process_id: get_u32("ParentProcessID"),
            image_file_path:   get_str("ImageFileName"),
            command_line:      get_str("CommandLine"),
            user_sid:          get_str("UserSID"),
            user_name:         get_str("UserName"),
            session_id:        get_u32("SessionID"),
            exit_code:         if event_id == 2 { get_u32("ExitCode") as i32 } else { 0 },
            integrity_level:   get_str("IntegrityLabel"),
        };

        if let Some(tx) = ETW_ASYNC_TX.get() {
            // Non-blocking: drop if the channel is full rather than deadlock
            let _ = tx.try_send(process_rec);
        }
    }

    fn get_active_username() -> String {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::RemoteDesktop::{
                WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSFreeMemory,
                WTS_CURRENT_SERVER_HANDLE, WTSUserName,
            };
            use windows::core::PWSTR;

            let session_id = WTSGetActiveConsoleSessionId();
            if session_id != 0xFFFFFFFF {
                let mut buffer = PWSTR::null();
                let mut bytes = 0u32;
                if WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE,
                    session_id,
                    WTSUserName,
                    &mut buffer,
                    &mut bytes,
                ).is_ok() && !buffer.is_null() {
                    let u16_slice = std::slice::from_raw_parts(buffer.0, (bytes as usize) / 2);
                    let s = String::from_utf16_lossy(u16_slice);
                    let trimmed = s.trim_matches('\0').trim().to_string();
                    WTSFreeMemory(buffer.0 as *mut _);
                    if !trimmed.is_empty() {
                        return trimmed;
                    }
                }
            }
        }
        std::env::var("USERNAME").unwrap_or_else(|_| "Akash.J".to_string())
    }

    fn resolve_process_user(raw_user: Option<String>, active_user: &str) -> String {
        match raw_user {
            Some(u) => {
                let trimmed = u.trim();
                if trimmed.is_empty() || trimmed == "User" || trimmed.starts_with("S-1-5-21-") {
                    active_user.to_string()
                } else if trimmed == "S-1-5-18" {
                    "SYSTEM".to_string()
                } else if trimmed == "S-1-5-19" {
                    "LOCAL SERVICE".to_string()
                } else if trimmed == "S-1-5-20" {
                    "NETWORK SERVICE".to_string()
                } else {
                    trimmed.to_string()
                }
            }
            None => active_user.to_string(),
        }
    }

    pub fn user_mode_process_poller() {
        let mut sys = sysinfo::System::new();
        let mut seen = std::collections::HashSet::new();
        let active_user = get_active_username();

        sys.refresh_processes();
        for (&pid, p) in sys.processes() {
            seen.insert(pid.as_u32());
            if let Some(tx) = ETW_ASYNC_TX.get() {
                let exe_path = p.exe().map(|e| e.to_string_lossy().to_string())
                    .unwrap_or_else(|| p.name().to_string());
                let cmd = p.cmd().join(" ");
                let user = resolve_process_user(p.user_id().map(|u| u.to_string()), &active_user);
                let rec = ProcessRecord {
                    event_id: 1,
                    process_id: pid.as_u32(),
                    parent_process_id: p.parent().map(|pp| pp.as_u32()).unwrap_or(0),
                    image_file_path: exe_path,
                    command_line: cmd,
                    user_sid: String::new(),
                    user_name: user,
                    session_id: 1,
                    exit_code: 0,
                    integrity_level: "Medium".to_string(),
                };
                let _ = tx.try_send(rec);
            }
        }

        loop {
            // 8 s interval for user-mode fallback avoids noticeable CPU usage
            std::thread::sleep(std::time::Duration::from_millis(8000));
            sys.refresh_processes();
            let current_pids: std::collections::HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
            let active_user = get_active_username();
            for (&pid, p) in sys.processes() {
                let u = pid.as_u32();
                if !seen.contains(&u) {
                    seen.insert(u);
                    if let Some(tx) = ETW_ASYNC_TX.get() {
                        let exe_path = p.exe().map(|e| e.to_string_lossy().to_string())
                            .unwrap_or_else(|| p.name().to_string());
                        let cmd = p.cmd().join(" ");
                        let user = resolve_process_user(p.user_id().map(|uid| uid.to_string()), &active_user);
                        let rec = ProcessRecord {
                            event_id: 1,
                            process_id: u,
                            parent_process_id: p.parent().map(|pp| pp.as_u32()).unwrap_or(0),
                            image_file_path: exe_path,
                            command_line: cmd,
                            user_sid: String::new(),
                            user_name: user,
                            session_id: 1,
                            exit_code: 0,
                            integrity_level: "Medium".to_string(),
                        };
                        let _ = tx.try_send(rec);
                    }
                }
            }
            seen.retain(|pid| current_pids.contains(pid));
        }
    }
}


#[cfg(not(windows))]
pub fn etw_thread_main() {}
