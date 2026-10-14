use crate::collectors::{hostname, now_ms};
use crate::pb::{telemetry_event::Payload, EventType, TelemetryEvent, WindowEvent};
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

const POLL_MS: u64 = 2000; // 2.0s foreground poll
const IDLE_THRESHOLD_SECS: u64 = 300; // 300s user inactivity threshold

#[derive(Clone, Debug)]
pub struct WindowSample {
    pub title: String,
    pub image: String,
    pub pid: u32,
    pub is_idle: bool,
    pub dwell_secs: u64,
}

pub struct WindowTracker {
    pub last_foreground_title: String,
    pub foreground_start: std::time::Instant,
}

impl WindowTracker {
    pub fn new() -> Self {
        Self {
            last_foreground_title: String::new(),
            foreground_start: std::time::Instant::now(),
        }
    }
}

pub async fn run(tx: Sender<TelemetryEvent>, agent_id: String) {
    let mut tracker = WindowTracker::new();
    let mut last_emitted_title = String::new();
    let mut poll_count = 0u32;

    loop {
        let samples = sample(&mut tracker);
        poll_count += 1;

        for s in samples {
            let is_incog = s.title.starts_with("[INCOGNITO]") || s.title.starts_with("[INPRIVATE]");
            // Emit if:
            // 1. Foreground title changed
            // 2. Or periodic refresh every 10 polls (~20s) to update dwell time
            // 3. Or it's an active incognito tab (always keep stealth monitor updated)
            if s.title != last_emitted_title || poll_count >= 10 || is_incog {
                if !is_incog {
                    last_emitted_title = s.title.clone();
                    poll_count = 0;
                }
                let ev = TelemetryEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    agent_id: agent_id.clone(),
                    hostname: hostname(),
                    timestamp_unix_ms: now_ms(),
                    event_type: EventType::WindowFocus as i32,
                    payload: Some(Payload::Window(WindowEvent {
                        window_title: s.title,
                        process_image: s.image,
                        process_id: s.pid,
                        is_idle: s.is_idle,
                        idle_seconds: s.dwell_secs,
                        observed_time_unix_ms: now_ms(),
                        document_path: String::new(),
                    })),
                };
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }

        sleep(Duration::from_millis(POLL_MS)).await;
    }
}

#[cfg(windows)]
#[derive(Clone)]
struct RawWin {
    hwnd: windows::Win32::Foundation::HWND,
    title: String,
    pid: u32,
    is_incognito: bool,
}

#[cfg(windows)]
fn sample(tracker: &mut WindowTracker) -> Vec<WindowSample> {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };

    #[link(name = "user32")]
    extern "system" {
        fn OpenInputDesktop(dw_flags: u32, f_inherit: i32, dw_desired_access: u32) -> isize;
        fn EnumDesktopWindows(
            h_desktop: isize,
            lpfn: unsafe extern "system" fn(HWND, LPARAM) -> BOOL,
            lparam: LPARAM,
        ) -> BOOL;
        fn CloseDesktop(h_desktop: isize) -> BOOL;
        fn IsIconic(hwnd: HWND) -> BOOL;
    }

    struct EnumCtx {
        top: Option<RawWin>,
        incognito: Option<RawWin>,
        inspected: usize,
    }

    unsafe extern "system" fn enum_desktop_win(h: HWND, lparam: LPARAM) -> BOOL {
        if IsWindowVisible(h).as_bool() && !IsIconic(h).as_bool() {
            let mut buf = [0u16; 512];
            let len = GetWindowTextW(h, &mut buf);
            if len > 0 {
                let text = String::from_utf16_lossy(&buf[..len as usize]);
                let t = text.trim();
                let is_noise = t.is_empty()
                    || t == "Program Manager"
                    || t == "Default IME"
                    || t == "MSCTFIME UI"
                    || t == "Windows Input Experience"
                    || t == "Desktop Window Manager"
                    || t == "Settings"
                    || t.starts_with("PopupHost")
                    || t == "Taskbar"
                    || t.starts_with("Cua.");

                if !is_noise {
                    let ctx = &mut *(lparam.0 as *mut EnumCtx);
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(h, Some(&mut pid));

                    let lower = t.to_lowercase();
                    let is_incog = lower.contains("incognito")
                        || lower.contains("inprivate")
                        || lower.contains("private browsing")
                        || lower.contains("private window")
                        || lower.contains("tor window")
                        || lower.contains("tor browser");

                    let win = RawWin {
                        hwnd: h,
                        title: t.to_string(),
                        pid,
                        is_incognito: is_incog,
                    };

                    if ctx.top.is_none() {
                        ctx.top = Some(win.clone());
                    }

                    if is_incog && ctx.incognito.is_none() {
                        ctx.incognito = Some(win);
                    }

                    ctx.inspected += 1;
                    if ctx.top.is_some() && (ctx.incognito.is_some() || ctx.inspected >= 25) {
                        return BOOL(0);
                    }
                }
            }
        }
        BOOL(1)
    }

    unsafe {
        let desk = OpenInputDesktop(0, 0, 0x01FF);
        let mut ctx = EnumCtx {
            top: None,
            incognito: None,
            inspected: 0,
        };

        if desk != 0 {
            let _ = EnumDesktopWindows(desk, enum_desktop_win, LPARAM(&mut ctx as *mut _ as isize));
            let _ = CloseDesktop(desk);
        }

        // If OpenInputDesktop failed or found no windows (e.g. secure desktop), fallback
        if ctx.top.is_none() {
            let fg = GetForegroundWindow();
            if fg.0 != 0 && IsWindowVisible(fg).as_bool() {
                let mut buf = [0u16; 512];
                let len = GetWindowTextW(fg, &mut buf);
                if len > 0 {
                    let text = String::from_utf16_lossy(&buf[..len as usize]);
                    let t = text.trim();
                    if !t.is_empty() {
                        let mut pid = 0u32;
                        GetWindowThreadProcessId(fg, Some(&mut pid));
                        let lower = t.to_lowercase();
                        let is_incog = lower.contains("incognito")
                            || lower.contains("inprivate")
                            || lower.contains("private browsing")
                            || lower.contains("private window")
                            || lower.contains("tor window");
                        ctx.top = Some(RawWin {
                            hwnd: fg,
                            title: t.to_string(),
                            pid,
                            is_incognito: is_incog,
                        });
                    }
                }
            }
        }

        let mut input_info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        let user_idle_secs = if GetLastInputInfo(&mut input_info).as_bool() {
            GetTickCount().saturating_sub(input_info.dwTime) as u64 / 1000
        } else {
            0
        };
        let is_idle = user_idle_secs >= IDLE_THRESHOLD_SECS;

        let mut out = Vec::new();

        if let Some(top_win) = ctx.top {
            if top_win.title != tracker.last_foreground_title {
                tracker.last_foreground_title = top_win.title.clone();
                tracker.foreground_start = std::time::Instant::now();
            }
            let dwell = tracker.foreground_start.elapsed().as_secs();
            let resolved_top = resolve_window(top_win.clone(), dwell, is_idle);
            out.push(resolved_top);

            if let Some(incog_win) = ctx.incognito {
                // If the incognito window is not the same as top window, also report it
                if incog_win.hwnd != top_win.hwnd && incog_win.title != top_win.title {
                    let resolved_incog = resolve_window(incog_win, 0, is_idle);
                    out.push(resolved_incog);
                }
            }
        } else {
            use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
            let session_id = WTSGetActiveConsoleSessionId();
            out.push(WindowSample {
                title: format!("Active Desktop Console (Session {})", session_id),
                image: "explorer.exe".to_string(),
                pid: session_id,
                is_idle,
                dwell_secs: 0,
            });
        }

        out
    }
}

#[cfg(windows)]
unsafe fn resolve_window(raw: RawWin, dwell_secs: u64, is_idle: bool) -> WindowSample {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let mut image = String::new();
    if raw.pid != 0 {
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, raw.pid) {
            let mut path_buf = [0u16; 512];
            let n = K32GetProcessImageFileNameW(handle, &mut path_buf);
            let full_device_path = String::from_utf16_lossy(&path_buf[..n as usize]);
            if let Some(pos) = full_device_path.rfind('\\') {
                image = full_device_path[pos + 1..].to_string();
            } else {
                image = full_device_path;
            }
            let _ = CloseHandle(handle);
        }
    }

    let mut title = raw.title;
    let lower_title = title.to_lowercase();

    if image.is_empty() {
        if lower_title.contains("zen") {
            image = "zen.exe".to_string();
        } else if lower_title.contains("edge") {
            image = "msedge.exe".to_string();
        } else if lower_title.contains("chrome") {
            image = "chrome.exe".to_string();
        } else if lower_title.contains("firefox") {
            image = "firefox.exe".to_string();
        } else if lower_title.contains("brave") {
            image = "brave.exe".to_string();
        } else if lower_title.contains("opera") {
            image = "opera.exe".to_string();
        } else if lower_title.contains("arc") {
            image = "arc.exe".to_string();
        } else if lower_title.contains("tor") {
            image = "tor.exe".to_string();
        } else if lower_title.contains("antigravity") {
            image = "antigravity.exe".to_string();
        } else if lower_title.contains("code") {
            image = "code.exe".to_string();
        } else {
            image = "explorer.exe".to_string();
        }
    }

    let is_incog = raw.is_incognito
        || lower_title.contains("incognito")
        || lower_title.contains("inprivate")
        || lower_title.contains("private browsing")
        || lower_title.contains("private window")
        || lower_title.contains("tor window")
        || lower_title.contains("tor browser");

    if is_incog && !title.starts_with("[INCOGNITO]") && !title.starts_with("[INPRIVATE]") {
        if lower_title.contains("inprivate") {
            title = format!("[INPRIVATE] {}", title);
        } else {
            title = format!("[INCOGNITO] {}", title);
        }
    }

    WindowSample {
        title,
        image,
        pid: raw.pid,
        is_idle,
        dwell_secs,
    }
}

#[cfg(not(windows))]
fn sample(_tracker: &mut WindowTracker) -> Vec<WindowSample> {
    Vec::new()
}
