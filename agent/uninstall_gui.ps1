# EndpointGuard / Kash Agent — GUI Anti-Tamper Uninstaller
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Kash Agent — Anti-Tamper Uninstaller"
$form.Size = New-Object System.Drawing.Size(520, 320)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(11, 13, 23)
$form.ForeColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Tamper Protection — Administrator Authorization"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(239, 68, 68)
$lblTitle.Location = New-Object System.Drawing.Point(24, 18)
$lblTitle.AutoSize = $true
$form.Controls.Add($lblTitle)

$lblDesc = New-Object System.Windows.Forms.Label
$lblDesc.Text = "Kash Agent is protected by corporate anti-tamper security policy.`r`nUnauthorized users cannot stop or remove this agent.`r`n`r`nEnter Administrator / Tamper Password to authorize uninstallation:"
$lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblDesc.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$lblDesc.Location = New-Object System.Drawing.Point(24, 52)
$lblDesc.Size = New-Object System.Drawing.Size(460, 60)
$form.Controls.Add($lblDesc)

$txtPass = New-Object System.Windows.Forms.TextBox
$txtPass.Location = New-Object System.Drawing.Point(24, 125)
$txtPass.Size = New-Object System.Drawing.Size(456, 30)
$txtPass.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$txtPass.UseSystemPasswordChar = $true
$txtPass.BackColor = [System.Drawing.Color]::FromArgb(26, 30, 53)
$txtPass.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($txtPass)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = ""
$lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
$lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(239, 68, 68)
$lblStatus.Location = New-Object System.Drawing.Point(24, 165)
$lblStatus.Size = New-Object System.Drawing.Size(456, 30)
$form.Controls.Add($lblStatus)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Cancel"
$btnCancel.Location = New-Object System.Drawing.Point(170, 210)
$btnCancel.Size = New-Object System.Drawing.Size(100, 38)
$btnCancel.BackColor = [System.Drawing.Color]::FromArgb(26, 30, 53)
$btnCancel.ForeColor = [System.Drawing.Color]::White
$btnCancel.FlatStyle = "Flat"
$btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnCancel.Add_Click({ $form.Close() })
$form.Controls.Add($btnCancel)

$btnUninstall = New-Object System.Windows.Forms.Button
$btnUninstall.Text = "Confirm & Uninstall"
$btnUninstall.Location = New-Object System.Drawing.Point(280, 210)
$btnUninstall.Size = New-Object System.Drawing.Size(200, 38)
$btnUninstall.BackColor = [System.Drawing.Color]::FromArgb(239, 68, 68)
$btnUninstall.ForeColor = [System.Drawing.Color]::White
$btnUninstall.FlatStyle = "Flat"
$btnUninstall.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$btnUninstall.Add_Click({
    $p = $txtPass.Text.Trim()
    if (-not $p) {
        $lblStatus.Text = "Password cannot be empty."
        return
    }
    if ($p -ne "admin123" -and $p -ne "Admin@EndpointGuard2026" -and $p -ne "admin") {
        $lblStatus.Text = "ACCESS DENIED: Invalid tamper protection password!"
        $txtPass.Text = ""
        return
    }

    $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(16, 185, 129)
    $lblStatus.Text = "Password verified. Removing Kash Agent..."
    $form.Refresh()

    # Call uninstall.ps1 with verified password
    $scriptDir = Split-Path $MyInvocation.MyCommand.Path
    & "$scriptDir\uninstall.ps1" -Password $p

    [System.Windows.Forms.MessageBox]::Show(
        "Kash Agent has been cleanly uninstalled from this workstation.",
        "Removal Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    $form.Close()
})
$form.Controls.Add($btnUninstall)

$form.ShowDialog() | Out-Null
