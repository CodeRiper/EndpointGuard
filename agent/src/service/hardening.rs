//! Service DACL hardening — locks down the EndpointGuard Windows Service
//! so that only SYSTEM and Administrators can control it.  Ordinary users
//! cannot stop, pause, or reconfigure the service.

use anyhow::Result;

/// Apply the restrictive SDDL to the service via `sc sdset`.
pub fn harden_service_dacl(service_name: &str) -> Result<()> {
    // D: — DACL
    //   (A;;CCLCSWRPWPDTLOCRRC;;;SY)  SYSTEM — full control
    //   (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)  Built-in Admins — full control
    //   (A;;CCLCSWLOCRRC;;;IU)  Interactive users — query / start / stop only
    // S: — SACL (audit all access failures from non-admin users)
    //   (AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)
    let sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)\
                 (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
                 (A;;CCLCSWLOCRRC;;;IU)\
                S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)";

    let output = std::process::Command::new("sc.exe")
        .args(["sdset", service_name, sddl])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "sc sdset failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Lock down the installation directory so only SYSTEM/Admins can write
    let install_dir = std::env::current_exe()?
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    std::process::Command::new("icacls.exe")
        .args([
            install_dir.to_string_lossy().as_ref(),
            "/inheritance:r",
            "/grant", "SYSTEM:(OI)(CI)F",
            "/grant", "Administrators:(OI)(CI)F",
            "/deny",  "Users:(OI)(CI)W",
        ])
        .status()?;

    Ok(())
}

/// Register and start the service via sc.exe.
/// Call this during installation (--install flag).
pub fn install_service(service_name: &str, display_name: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_path = exe.to_string_lossy();

    std::process::Command::new("sc.exe")
        .args([
            "create", service_name,
            "binPath=",  &format!("\"{}\"", exe_path),
            "DisplayName=", display_name,
            "start=", "auto",
            "obj=", "LocalSystem",
            "type=", "own",
        ])
        .status()?;

    std::process::Command::new("sc.exe")
        .args(["description", service_name,
               "EndpointGuard unified EDR/RMM agent"])
        .status()?;

    // Apply DACL hardening immediately after creation
    harden_service_dacl(service_name)?;

    std::process::Command::new("sc.exe")
        .args(["start", service_name])
        .status()?;

    Ok(())
}
