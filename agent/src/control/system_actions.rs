//! Win32 system-control actions dispatched by the server:
//! lock screen, force sign-out, popup dialog, and power actions
//! (shutdown/restart with a countdown + on-screen message, and cancel).

use anyhow::Result;

// ── Lock workstation ────────────────────────────────────────────────────
pub fn lock_screen() -> bool {
    #[cfg(windows)]
    {
        let res = unsafe {
            use windows::Win32::System::Shutdown::LockWorkStation;
            LockWorkStation().is_ok()
        };
        if !res {
            let _ = std::process::Command::new("rundll32.exe")
                .args(["user32.dll,LockWorkStation"])
                .status();
        }
        true
    }
    #[cfg(not(windows))]
    false
}

// ── Sign out the active console session ─────────────────────────────────
pub fn sign_out() -> bool {
    #[cfg(windows)]
    {
        unsafe {
            use windows::Win32::System::RemoteDesktop::{
                WTSLogoffSession, WTSGetActiveConsoleSessionId, WTS_CURRENT_SERVER_HANDLE,
            };
            let session = WTSGetActiveConsoleSessionId();
            let _ = WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, session, false);
        }
        let _ = std::process::Command::new("shutdown.exe")
            .args(["/l", "/f"])
            .status();
        true
    }
    #[cfg(not(windows))]
    false
}

/// Acquires SE_SHUTDOWN_NAME on the current process token. Both
/// power_action and cancel_power_action need it — InitiateSystemShutdownExW
/// and AbortSystemShutdownW both require the privilege to be enabled first.
#[cfg(windows)]
unsafe fn acquire_shutdown_privilege() -> Result<()> {
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken,
    };
    use windows::core::PCWSTR;

    let mut token = windows::Win32::Foundation::HANDLE::default();
    OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    )?;

    let priv_name: Vec<u16> = "SeShutdownPrivilege\0".encode_utf16().collect();
    let mut luid = windows::Win32::Foundation::LUID::default();
    LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(priv_name.as_ptr()), &mut luid)?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
    Ok(())
}

/// Shutdown AND restart share this one function — `restart` picks which.
/// `delay_seconds` is the countdown Windows shows before it fires,
/// `message` is the on-screen text shown to the signed-in user during that
/// countdown, and `force_apps_closed` controls whether open apps with
/// unsaved work get force-closed instead of blocking the shutdown.
pub fn power_action(
    restart: bool,
    delay_seconds: u32,
    message: &str,
    force_apps_closed: bool,
) -> Result<()> {
    #[cfg(windows)]
    {
        let api_res = unsafe {
            let _ = acquire_shutdown_privilege();
            let mut wide_message: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
            windows::Win32::System::Shutdown::InitiateSystemShutdownExW(
                windows::core::PCWSTR::null(),
                windows::core::PWSTR(wide_message.as_mut_ptr()),
                delay_seconds,
                force_apps_closed,
                restart,
                windows::Win32::System::Shutdown::SHTDN_REASON_FLAG_PLANNED,
            )
        };

        if api_res.is_err() {
            let action_flag = if restart { "/r" } else { "/s" };
            let delay_str = delay_seconds.to_string();
            let mut cmd = std::process::Command::new("shutdown.exe");
            cmd.args([action_flag, "/t", &delay_str, "/c", message]);
            if force_apps_closed {
                cmd.arg("/f");
            }
            let _ = cmd.status();
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (restart, delay_seconds, message, force_apps_closed);
        Ok(())
    }
}

/// Cancels a previously-issued, still-pending shutdown/restart.
pub fn cancel_power_action() -> Result<()> {
    #[cfg(windows)]
    {
        unsafe {
            let _ = acquire_shutdown_privilege();
            let _ = windows::Win32::System::Shutdown::AbortSystemShutdownW(windows::core::PCWSTR::null());
        }
        let _ = std::process::Command::new("shutdown.exe").arg("/a").status();
        Ok(())
    }
    #[cfg(not(windows))]
    Ok(())
}

// ── WTSSendMessage popup dialog ─────────────────────────────────────────
pub fn send_popup(title: &str, message: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let title_s = title.to_string();
        let msg_s = message.to_string();

        // 1. Spawning a foreground interactive MessageBoxW thread
        let title_c = title_s.clone();
        let msg_c = msg_s.clone();
        std::thread::spawn(move || {
            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_TOPMOST, MB_SETFOREGROUND, MB_SYSTEMMODAL};
            use windows::core::PCWSTR;
            let wide_t: Vec<u16> = title_c.encode_utf16().chain(Some(0)).collect();
            let wide_m: Vec<u16> = msg_c.encode_utf16().chain(Some(0)).collect();
            unsafe {
                MessageBoxW(
                    windows::Win32::Foundation::HWND(0),
                    PCWSTR(wide_m.as_ptr()),
                    PCWSTR(wide_t.as_ptr()),
                    MB_OK | MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL,
                );
            }
        });

        // 2. WTSSendMessage to console session (works across terminal services and remote desktop)
        unsafe {
            use windows::Win32::System::RemoteDesktop::{
                WTSSendMessageW, WTSGetActiveConsoleSessionId, WTS_CURRENT_SERVER_HANDLE,
            };
            use windows::Win32::UI::WindowsAndMessaging::{
                MESSAGEBOX_STYLE, MESSAGEBOX_RESULT,
            };

            let session_id = WTSGetActiveConsoleSessionId();
            let mut wide_title: Vec<u16> = title_s.encode_utf16().chain(Some(0)).collect();
            let mut wide_msg: Vec<u16> = msg_s.encode_utf16().chain(Some(0)).collect();
            let mut response = MESSAGEBOX_RESULT(0);

            let _ = WTSSendMessageW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                windows::core::PWSTR(wide_title.as_mut_ptr()),
                (wide_title.len() * 2) as u32,
                windows::core::PWSTR(wide_msg.as_mut_ptr()),
                (wide_msg.len() * 2) as u32,
                MESSAGEBOX_STYLE(0), // MB_OK
                0,                   // timeout
                &mut response,
                false,
            );
        }

        // 3. Fallback PowerShell GUI popup to guarantee display even on locked session unlocking
        let _ = std::process::Command::new("powershell.exe")
            .args([
                "-WindowStyle", "Hidden", "-Command",
                &format!(
                    "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; [System.Windows.Forms.MessageBox]::Show({}, {})",
                    serde_json::to_string(&message).unwrap_or_default(),
                    serde_json::to_string(&title).unwrap_or_default()
                )
            ])
            .spawn();

        Ok(())
    }
    #[cfg(not(windows))]
    Ok(())
}

// ── Kill Process ──────────────────────────────────────────────────────────
pub fn kill_process(pid: u32) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        TerminateProcess(handle, 1)?;
        Ok(())
    }
    #[cfg(not(windows))]
    Ok(())
}

// ── Uninstall Agent Service ──────────────────────────────────────────────
pub fn uninstall_agent() -> Result<()> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("sc.exe").args(["stop", "EndpointGuard"]).status();
        let _ = Command::new("sc.exe").args(["delete", "EndpointGuard"]).status();
        // Detached thread so this command returns RPC result before terminating
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(600));
            std::process::exit(0);
        });
    }
    Ok(())
}

// ── Real Remote Shell Execution ──────────────────────────────────────────
pub fn exec_shell_command(cmd: &str) -> Result<String> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", cmd])
            .output()?;
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        let err = String::from_utf8_lossy(&output.stderr);
        if !err.is_empty() {
            if !text.is_empty() { text.push_str("\n"); }
            text.push_str(&err);
        }
        if text.trim().is_empty() {
            text = "(command executed with no output)".to_string();
        }
        Ok(text)
    }
    #[cfg(not(windows))]
    Ok(format!("executed: {}", cmd))
}

// ── Remote Input: Mouse Click Injection ──────────────────────────────────
pub fn inject_mouse_click(x: i32, y: i32) -> Result<()> {
    inject_mouse_action("click", x, y)
}

pub fn inject_mouse_action(action: &str, x: i32, y: i32) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics, SetCursorPos, SM_CXSCREEN, SM_CYSCREEN,
        };
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            mouse_event, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        };
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        let target_x = if x > 1280 || (x > 0 && screen_w <= 1280) {
            x.clamp(0, screen_w)
        } else if screen_w > 0 {
            (x * screen_w) / 1280
        } else {
            x
        };
        let target_y = if y > 720 || (y > 0 && screen_h <= 720) {
            y.clamp(0, screen_h)
        } else if screen_h > 0 {
            (y * screen_h) / 720
        } else {
            y
        };
        let _ = SetCursorPos(target_x, target_y);

        match action {
            "move" => {}
            "mousedown" => {
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
            }
            "mouseup" => {
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            }
            "right_click" => {
                mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
                std::thread::sleep(std::time::Duration::from_millis(30));
                mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
            }
            "double_click" => {
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                std::thread::sleep(std::time::Duration::from_millis(30));
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                std::thread::sleep(std::time::Duration::from_millis(80));
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                std::thread::sleep(std::time::Duration::from_millis(30));
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            }
            _ => {
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                std::thread::sleep(std::time::Duration::from_millis(30));
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            }
        }
    }
    Ok(())
}

// ── Remote Input: Keyboard Key Combo Injection ───────────────────────────
pub fn inject_key_combo(combo: &str) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            keybd_event, KEYEVENTF_KEYUP, VK_LWIN, VK_CONTROL, VK_MENU, VK_DELETE, VK_TAB,
            VK_RETURN, VK_BACK, VK_ESCAPE, VK_SPACE, VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT,
        };
        match combo {
            "Win+R" => {
                keybd_event(VK_LWIN.0 as u8, 0, Default::default(), 0);
                keybd_event(b'R', 0, Default::default(), 0);
                keybd_event(b'R', 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_LWIN.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Win+D" => {
                keybd_event(VK_LWIN.0 as u8, 0, Default::default(), 0);
                keybd_event(b'D', 0, Default::default(), 0);
                keybd_event(b'D', 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_LWIN.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Win+E" => {
                keybd_event(VK_LWIN.0 as u8, 0, Default::default(), 0);
                keybd_event(b'E', 0, Default::default(), 0);
                keybd_event(b'E', 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_LWIN.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Alt+Tab" => {
                keybd_event(VK_MENU.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_TAB.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_TAB.0 as u8, 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_MENU.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Ctrl+Alt+Del" => {
                keybd_event(VK_CONTROL.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_MENU.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_DELETE.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_DELETE.0 as u8, 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_MENU.0 as u8, 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_CONTROL.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Enter" => {
                keybd_event(VK_RETURN.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_RETURN.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Backspace" => {
                keybd_event(VK_BACK.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_BACK.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Tab" => {
                keybd_event(VK_TAB.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_TAB.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Escape" => {
                keybd_event(VK_ESCAPE.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_ESCAPE.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "Space" => {
                keybd_event(VK_SPACE.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_SPACE.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "ArrowUp" => {
                keybd_event(VK_UP.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_UP.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            "ArrowDown" => {
                keybd_event(VK_DOWN.0 as u8, 0, Default::default(), 0);
                keybd_event(VK_DOWN.0 as u8, 0, KEYEVENTF_KEYUP, 0);
            }
            _ => {
                for b in combo.bytes() {
                    keybd_event(b, 0, Default::default(), 0);
                    keybd_event(b, 0, KEYEVENTF_KEYUP, 0);
                }
            }
        }
    }
    Ok(())
}

// ── Remote File Manager Operations ────────────────────────────────────────

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn list_directory(target_path: &str) -> Result<String> {
    use std::fmt::Write;
    let p = target_path.trim();

    #[cfg(windows)]
    if p.is_empty() || p == "/" || p == "\\" || p == "DRIVES" || p.eq_ignore_ascii_case("THIS_PC") {
        let mut json = String::from("[");
        let mut first = true;
        for drive in b'C'..=b'Z' {
            let drive_path = format!("{}:\\", drive as char);
            if std::path::Path::new(&drive_path).exists() {
                if !first { json.push(','); }
                first = false;
                let _ = write!(
                    json,
                    r#"{{"name":"Local Disk ({}:)","is_dir":true,"size":0,"size_formatted":"--","modified":"System Drive","path":{:?},"sensitivity":"STANDARD","ext":"drive","file_type":"Local Disk"}}"#,
                    drive as char, drive_path
                );
            }
        }
        json.push(']');
        return Ok(json);
    }

    // Resolve quick navigation shortcuts and environment variables
    let resolved_path_str: String = if p.eq_ignore_ascii_case("QUICK:DESKTOP") {
        std::env::var("USERPROFILE").map(|u| format!("{}\\Desktop", u)).unwrap_or_else(|_| "C:\\Users".into())
    } else if p.eq_ignore_ascii_case("QUICK:DOCUMENTS") {
        std::env::var("USERPROFILE").map(|u| format!("{}\\Documents", u)).unwrap_or_else(|_| "C:\\Users".into())
    } else if p.eq_ignore_ascii_case("QUICK:DOWNLOADS") {
        std::env::var("USERPROFILE").map(|u| format!("{}\\Downloads", u)).unwrap_or_else(|_| "C:\\Users".into())
    } else if p.eq_ignore_ascii_case("QUICK:USERPROFILE") {
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users".into())
    } else if p.eq_ignore_ascii_case("QUICK:USERS") {
        "C:\\Users".into()
    } else if p.eq_ignore_ascii_case("QUICK:PROGRAMFILES") {
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into())
    } else if p.eq_ignore_ascii_case("QUICK:SYSTEM32") {
        std::env::var("SystemRoot").map(|s| format!("{}\\System32", s)).unwrap_or_else(|_| "C:\\Windows\\System32".into())
    } else if p.contains('%') {
        let mut exp = p.to_string();
        if let Ok(val) = std::env::var("USERPROFILE") { exp = exp.replace("%USERPROFILE%", &val); }
        if let Ok(val) = std::env::var("SystemRoot") { exp = exp.replace("%SystemRoot%", &val).replace("%SYSTEMROOT%", &val); }
        if let Ok(val) = std::env::var("WINDIR") { exp = exp.replace("%WINDIR%", &val).replace("%windir%", &val); }
        if let Ok(val) = std::env::var("ProgramFiles") { exp = exp.replace("%ProgramFiles%", &val); }
        if let Ok(val) = std::env::var("APPDATA") { exp = exp.replace("%APPDATA%", &val); }
        if let Ok(val) = std::env::var("LOCALAPPDATA") { exp = exp.replace("%LOCALAPPDATA%", &val); }
        if let Ok(val) = std::env::var("TEMP") { exp = exp.replace("%TEMP%", &val); }
        exp
    } else {
        p.to_string()
    };

    let dir_path = if resolved_path_str.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    } else {
        std::path::PathBuf::from(&resolved_path_str)
    };

    if !dir_path.exists() {
        return Err(anyhow::anyhow!("Directory path does not exist on endpoint: {}", dir_path.display()));
    }

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(e) => e,
        Err(err) => {
            return Err(anyhow::anyhow!("Cannot access directory {}: {}", dir_path.display(), err));
        }
    };

    struct EntryItem {
        name: String,
        is_dir: bool,
        size: u64,
        size_str: String,
        modified: String,
        full_path: String,
        sensitivity: &'static str,
        ext: String,
        file_type: String,
    }

    let mut folders = Vec::new();
    let mut files = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let metadata = entry.metadata().ok();
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        let size_str = if is_dir { "--".to_string() } else { format_bytes(size) };

            let modified = metadata
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Local> = t.into();
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "Unknown".to_string());

            let full_path = entry.path().to_string_lossy().to_string();
            let lower = name.to_lowercase();
            let ext = std::path::Path::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            let sensitivity = if lower.ends_with(".key") || lower.ends_with(".pem") || lower.ends_with(".kdbx") || lower.ends_with(".env") || lower.contains("secret") || lower.contains("password") {
                "CRITICAL"
            } else if lower.ends_with(".xlsx") || lower.ends_with(".csv") || lower.ends_with(".sql") || lower.ends_with(".pdf") || lower.contains("financial") {
                "CONFIDENTIAL"
            } else if lower.ends_with(".rs") || lower.ends_with(".go") || lower.ends_with(".md") || lower.ends_with(".json") {
                "INTERNAL"
            } else {
                "STANDARD"
            };

            let file_type = if is_dir {
                "File folder".to_string()
            } else {
                match ext.as_str() {
                    "exe" => "Application".to_string(),
                    "dll" => "Application extension".to_string(),
                    "sys" => "System file".to_string(),
                    "txt" => "Text Document".to_string(),
                    "pdf" => "Adobe Acrobat Document".to_string(),
                    "docx" | "doc" => "Microsoft Word Document".to_string(),
                    "xlsx" | "xls" => "Microsoft Excel Worksheet".to_string(),
                    "csv" => "Comma-Separated Values".to_string(),
                    "zip" | "rar" | "7z" | "tar" | "gz" => "Compressed Archive".to_string(),
                    "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" => "Image File".to_string(),
                    "mp4" | "mkv" | "avi" | "mov" => "Video File".to_string(),
                    "mp3" | "wav" | "flac" => "Audio File".to_string(),
                    "ps1" => "PowerShell Script".to_string(),
                    "bat" | "cmd" => "Windows Batch File".to_string(),
                    "rs" => "Rust Source File".to_string(),
                    "go" => "Go Source File".to_string(),
                    "py" => "Python Source File".to_string(),
                    "js" | "ts" => "JavaScript File".to_string(),
                    "json" => "JSON Configuration".to_string(),
                    "xml" => "XML Document".to_string(),
                    "log" => "Log File".to_string(),
                    "ini" | "cfg" | "toml" | "yaml" | "yml" => "Configuration File".to_string(),
                    "" => "File".to_string(),
                    other => format!("{} File", other.to_uppercase()),
                }
            };

            let item = EntryItem {
                name,
                is_dir,
                size,
                size_str,
                modified,
                full_path,
                sensitivity,
                ext,
                file_type,
            };

        if is_dir {
            folders.push(item);
        } else {
            files.push(item);
        }
    }

    // Windows File Explorer sorting: folders first A-Z, then files A-Z
    folders.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    let mut json = String::from("[");
    let mut first = true;
    for item in folders.into_iter().chain(files.into_iter()) {
        if !first { json.push(','); }
        first = false;
        let _ = write!(
            json,
            r#"{{"name":{:?},"is_dir":{},"size":{},"size_formatted":{:?},"modified":{:?},"path":{:?},"sensitivity":{:?},"ext":{:?},"file_type":{:?}}}"#,
            item.name, item.is_dir, item.size, item.size_str, item.modified, item.full_path, item.sensitivity, item.ext, item.file_type
        );
    }
    json.push(']');
    Ok(json)
}

pub fn read_file_hex(target_path: &str) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(target_path)?;
    let mut buf = Vec::new();
    // Allow reading up to 50 MB
    file.by_ref().take(50 * 1024 * 1024).read_to_end(&mut buf)?;
    Ok(hex::encode(&buf))
}

pub fn delete_file_or_dir(target_path: &str) -> Result<String> {
    let p = std::path::Path::new(target_path);
    if !p.exists() {
        return Err(anyhow::anyhow!("Path does not exist: {}", target_path));
    }
    if p.is_dir() {
        std::fs::remove_dir_all(p)?;
        Ok(format!("Directory deleted successfully: {}", target_path))
    } else {
        std::fs::remove_file(p)?;
        Ok(format!("File deleted successfully: {}", target_path))
    }
}

pub fn write_file_base64(target_path: &str, content_b64: &str) -> Result<usize> {
    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD.decode(content_b64.trim())?;
    let path = std::path::Path::new(target_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &data)?;
    Ok(data.len())
}



