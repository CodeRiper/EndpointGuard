//! DLP: clipboard monitoring + USB device arrival/removal.

use crate::collectors::{hostname, now_ms};
use crate::pb::{
    telemetry_event::Payload, ClipboardDlpEvent, EventType, TelemetryEvent, UsbDeviceEvent,
};
use regex::Regex;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

const POLL_MS: u64 = 750;

pub async fn run(tx: Sender<TelemetryEvent>, agent_id: String) {
    let patterns = build_patterns();
    let mut last_seq: u32 = 0;

    // Spawn USB watcher on a dedicated OS thread (needs a Win32 message loop)
    let usb_tx = tx.clone();
    let usb_aid = agent_id.clone();
    std::thread::spawn(move || {
        #[cfg(windows)]
        usb_watch_loop(usb_tx, usb_aid);
    });

    // Clipboard polling loop
    loop {
        if let Some(seq) = clipboard_sequence() {
            if seq != last_seq {
                last_seq = seq;
                if let Some(text) = read_clipboard_text() {
                    if let Some(category) = classify(&text, &patterns) {
                        let source = clipboard_owner_process();
                        let ev = TelemetryEvent {
                            event_id:          Uuid::new_v4().to_string(),
                            agent_id:          agent_id.clone(),
                            hostname:          hostname(),
                            timestamp_unix_ms: now_ms(),
                            event_type:        EventType::DlpClipboard as i32,
                            payload: Some(Payload::ClipboardDlp(ClipboardDlpEvent {
                                source_process:        source,
                                match_category:        category,
                                match_count:           1,
                                observed_time_unix_ms: now_ms(),
                            })),
                        };
                        if tx.send(ev).await.is_err() { return; }
                    }
                }
            }
        }
        sleep(Duration::from_millis(POLL_MS)).await;
    }
}

// ── Pattern matching ─────────────────────────────────────────────────────────

fn build_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        ("CARD_NUMBER",  Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap()),
        ("JWT",          Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap()),
        ("API_KEY",      Regex::new(r"\b(sk|pk|api|token)_[A-Za-z0-9_]{16,}\b").unwrap()),
        ("PRIVATE_KEY",  Regex::new(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----").unwrap()),
        ("PASSWORD_KV",  Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{8,}").unwrap()),
    ]
}

fn classify(text: &str, patterns: &[(&'static str, Regex)]) -> Option<String> {
    patterns.iter()
        .find(|(_, re)| re.is_match(text))
        .map(|(name, _)| (*name).to_string())
}

// ── Win32 clipboard ──────────────────────────────────────────────────────────

#[cfg(windows)]
fn clipboard_sequence() -> Option<u32> {
    use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
    Some(unsafe { GetClipboardSequenceNumber() })
}

#[cfg(windows)]
fn read_clipboard_text() -> Option<String> {
    use windows::Win32::Foundation::{HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    unsafe {
        if OpenClipboard(HWND(0)).is_err() { return None; }
        let result = (|| {
            if let Ok(h) = GetClipboardData(CF_UNICODETEXT.0 as u32) {
                let ptr = GlobalLock(HGLOBAL(h.0 as *mut _));
                if !ptr.is_null() {
                    let len = wcslen(ptr as *const u16);
                    let wide = std::slice::from_raw_parts(ptr as *const u16, len);
                    let text = String::from_utf16_lossy(wide);
                    let _ = GlobalUnlock(HGLOBAL(h.0 as *mut _));
                    return Some(text);
                }
            }
            if let Ok(h) = GetClipboardData(1) {
                let ptr = GlobalLock(HGLOBAL(h.0 as *mut _));
                if !ptr.is_null() {
                    let cstr = std::ffi::CStr::from_ptr(ptr as *const i8);
                    let text = cstr.to_string_lossy().to_string();
                    let _ = GlobalUnlock(HGLOBAL(h.0 as *mut _));
                    return Some(text);
                }
            }
            None
        })();
        let _ = CloseClipboard();
        result
    }
}

#[cfg(windows)]
fn clipboard_owner_process() -> String {
    use windows::Win32::System::DataExchange::GetClipboardOwner;
    use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    unsafe {
        let hwnd = GetClipboardOwner();
        if hwnd.0 == 0 { return String::new(); }
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            let mut buf = [0u16; 512];
            let n = K32GetProcessImageFileNameW(h, &mut buf);
            let img = String::from_utf16_lossy(&buf[..n as usize]);
            let _ = windows::Win32::Foundation::CloseHandle(h);
            return img;
        }
        String::new()
    }
}

#[cfg(windows)]
unsafe fn wcslen(mut p: *const u16) -> usize {
    let mut n = 0;
    while *p != 0 { p = p.add(1); n += 1; }
    n
}

// ── USB device monitoring ─────────────────────────────────────────────────────

#[cfg(windows)]
fn usb_watch_loop(tx: Sender<TelemetryEvent>, agent_id: String) {
    use windows::core::GUID;
    // GUID_DEVINTERFACE_VOLUME — detects volume (USB/CD/etc.) arrival
    let guid_volume = GUID {
        data1: 0x53f5630d, data2: 0xb6bf, data3: 0x11d0,
        data4: [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
    };

    // We use a simple message-only window to receive WM_DEVICECHANGE.
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW,
        RegisterClassExW, TranslateMessage, DBT_DEVICEARRIVAL,
        DBT_DEVICEREMOVECOMPLETE, HWND_MESSAGE, MSG,
        WM_DEVICECHANGE, WNDCLASSEXW, WS_OVERLAPPED,
        RegisterDeviceNotificationW, DEV_BROADCAST_DEVICEINTERFACE_W,
        DBT_DEVTYP_DEVICEINTERFACE, DEVICE_NOTIFY_WINDOW_HANDLE,
    };

    unsafe extern "system" fn wnd_proc(
        hwnd: windows::Win32::Foundation::HWND,
        msg: u32,
        wparam: windows::Win32::Foundation::WPARAM,
        lparam: windows::Win32::Foundation::LPARAM,
    ) -> windows::Win32::Foundation::LRESULT {
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    unsafe {
        // Register a minimal window class
        let class_name: Vec<u16> = "EG_USB_WND\0".encode_utf16().collect();
        let wc = WNDCLASSEXW {
            cbSize:    std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
            lpfnWndProc:   Some(wnd_proc),
            ..Default::default()
        };
        RegisterClassExW(&wc);

        let hwnd = CreateWindowExW(
            Default::default(),
            windows::core::PCWSTR(class_name.as_ptr()),
            windows::core::PCWSTR::null(),
            WS_OVERLAPPED, 0, 0, 0, 0,
            HWND_MESSAGE, None, None, None,
        );

        let filter = DEV_BROADCAST_DEVICEINTERFACE_W {
            dbcc_size:       std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() as u32,
            dbcc_devicetype: DBT_DEVTYP_DEVICEINTERFACE.0,
            dbcc_classguid:  guid_volume,
            ..Default::default()
        };
        RegisterDeviceNotificationW(
            windows::Win32::Foundation::HANDLE(hwnd.0),
            &filter as *const _ as *const _,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        );

        // Message loop
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if msg.message == WM_DEVICECHANGE {
                let action = msg.wParam.0 as u32;
                let arrival = action == DBT_DEVICEARRIVAL;
                let removal = action == DBT_DEVICEREMOVECOMPLETE;

                if arrival || removal {
                    let ev = TelemetryEvent {
                        event_id:          Uuid::new_v4().to_string(),
                        agent_id:          agent_id.clone(),
                        hostname:          hostname(),
                        timestamp_unix_ms: now_ms(),
                        event_type:        EventType::UsbDevice as i32,
                        payload: Some(Payload::UsbDevice(UsbDeviceEvent {
                            action:                if arrival { "ARRIVAL".into() } else { "REMOVAL".into() },
                            observed_time_unix_ms: now_ms(),
                            ..Default::default()
                        })),
                    };
                    let _ = tx.blocking_send(ev);
                }
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(not(windows))]
fn clipboard_sequence() -> Option<u32> { None }
#[cfg(not(windows))]
fn read_clipboard_text() -> Option<String> { None }
#[cfg(not(windows))]
fn clipboard_owner_process() -> String { String::new() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard() {
        let seq = clipboard_sequence();
        let text = read_clipboard_text();
        println!("TEST CLIPBOARD: seq={:?} text={:?}", seq, text);
    }
}

