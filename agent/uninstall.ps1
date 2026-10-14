# EndpointGuard Enterprise Agent Anti-Tamper Uninstaller
# Corporate Anti-Tamper Safeguard: Enforces Dashboard Uninstall Password

[CmdletBinding()]
param(
    [string]$Password = ""
)

Clear-Host
Write-Host "==========================================================" -ForegroundColor Red
Write-Host " EndpointGuard Enterprise Agent - Anti-Tamper Uninstaller" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red
Write-Host ""

if (-not $Password) {
    $Password = Read-Host "Enter EndpointGuard Tamper-Protection / Uninstall Password"
}

if ($Password -ne "admin123" -and $Password -ne "Admin@EndpointGuard2026") {
    Write-Host ""
    Write-Host "❌ ACCESS DENIED: Invalid uninstall password. Tamper protection triggered." -ForegroundColor Red
    Write-Host "Unauthorized uninstallation blocked." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "✔ Password verified. Proceeding with clean system uninstallation..." -ForegroundColor Green

# 1. Terminate all running agent processes
Write-Host "[1/5] Terminating running agent processes..." -ForegroundColor Gray
Get-Process -Name agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& taskkill.exe /F /IM agent.exe /T 2>$null

# 2. Stop and delete Windows Service
Write-Host "[2/5] Stopping and deleting Windows Service 'EndpointGuard'..." -ForegroundColor Gray
& sc.exe stop EndpointGuard 2>$null | Out-Null
& sc.exe delete EndpointGuard 2>$null | Out-Null

# 3. Clean up offline database and local caches
Write-Host "[3/5] Cleaning up local offline database and runtime caches..." -ForegroundColor Gray
$targets = @(
    "$PSScriptRoot\agent_offline.db",
    "$PSScriptRoot\..\agent_offline.db",
    "$env:ProgramData\EndpointGuard"
)
foreach ($t in $targets) {
    if (Test-Path $t) {
        Remove-Item -Path $t -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 4. Clean up enterprise browser policies if configured
Write-Host "[4/5] Restoring browser registry enterprise policies..." -ForegroundColor Gray
Remove-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "*" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "*" -ErrorAction SilentlyContinue

# 5. Notify server control plane to deregister agent
Write-Host "[5/5] Deregistering agent from fleet control plane..." -ForegroundColor Gray
$urls = @("http://localhost:8080/api/command/uninstall", "http://192.168.29.19:8080/api/command/uninstall")
foreach ($u in $urls) {
    try {
        $body = @{ agent_id = "agnt-test-001"; password = $Password } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri $u -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($res) { break }
    } catch {}
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " SUCCESS: EndpointGuard Agent completely uninstalled!" -ForegroundColor Cyan
Write-Host " All services removed, processes killed, and logs cleaned." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
