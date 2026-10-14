//! Enterprise browser policy provisioner.
//!
//! Writes registry keys under Chrome and Edge GPO paths so that:
//!   1. The EndpointGuard monitoring extension is force-installed.
//!   2. The native messaging host (bridge to agent.exe) is registered.
//!
//! Must run elevated (as SYSTEM or Administrator).

use anyhow::Result;

#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegSetValueExW, RegCloseKey,
    HKEY_LOCAL_MACHINE, HKEY, KEY_WRITE,
    REG_SZ, REG_OPTION_NON_VOLATILE,
};

pub fn provision_enterprise_browser_policies(
    extension_id: &str,
    update_url: &str,
) -> Result<()> {
    let force_install_value = format!("{};{}", extension_id, update_url);

    // Chrome policy
    write_registry_policy(
        r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
        "1",
        &force_install_value,
    )?;

    // Edge policy
    write_registry_policy(
        r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
        "1",
        &force_install_value,
    )?;

    // Register native messaging host for Chrome
    let exe_path = std::env::current_exe()?;
    let host_manifest = serde_json_lite(
        extension_id,
        exe_path.to_string_lossy().as_ref(),
    );

    // Write the manifest file
    let manifest_dir  = std::env::var("ProgramData")
        .unwrap_or_else(|_| "C:\\ProgramData".into());
    let manifest_path = format!(
        "{}\\EndpointGuard\\native_host.json", manifest_dir
    );
    if let Some(p) = std::path::Path::new(&manifest_path).parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(&manifest_path, &host_manifest)?;

    // Register the host path in Chrome registry
    write_registry_policy(
        r"SOFTWARE\Google\Chrome\NativeMessagingHosts\com.enterprise.monitor",
        "",
        &manifest_path,
    )?;
    write_registry_policy(
        r"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.enterprise.monitor",
        "",
        &manifest_path,
    )?;

    Ok(())
}

fn write_registry_policy(subkey: &str, value_name: &str, data: &str) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        let wide_subkey: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let wide_name:   Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
        let wide_data:   Vec<u16> = data.encode_utf16().chain(Some(0)).collect();
        let data_bytes: &[u8] = std::slice::from_raw_parts(
            wide_data.as_ptr() as *const u8,
            wide_data.len() * 2,
        );

        let mut hkey = HKEY::default();
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide_subkey.as_ptr()),
            0, None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None, &mut hkey, None,
        ).ok()?;

        RegSetValueExW(
            hkey,
            windows::core::PCWSTR(wide_name.as_ptr()),
            0, REG_SZ,
            Some(data_bytes),
        ).ok()?;

        RegCloseKey(hkey).ok()?;
    }
    Ok(())
}

/// Minimal JSON manifest — no external serde dependency needed.
fn serde_json_lite(extension_id: &str, exe_path: &str) -> String {
    format!(
        r#"{{
  "name": "com.enterprise.monitor",
  "description": "EndpointGuard native messaging bridge",
  "path": "{}",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://{}/" ]
}}"#,
        exe_path.replace('\\', "\\\\"),
        extension_id
    )
}
