<#
.SYNOPSIS
  Installs the EndpointGuard CONTROL SERVER (not the agent — see deploy.ps1
  for that) as a Windows Service.

.DESCRIPTION
  Same server binary as install-linux.sh installs on Linux; only the service
  wrapper differs. Run this on the Windows machine that will BE your control
  server — the one your dashboard and agents connect to.

  Windows services don't read a registry "Parameters" key as environment
  variables automatically, so this installs a tiny launcher wrapper
  (eg-server-launch.ps1) that reads them from the registry and re-execs the
  real binary with the right flags — that's the one thing that differs from
  the Linux systemd unit, which can set environment variables directly.

.EXAMPLE
  .\install-windows.ps1 -GrpcPort 4443 -HttpPort 8080 `
      -CertDir "C:\ProgramData\EndpointGuard\certs" `
      -ClickHouseDsn "clickhouse://localhost:9000/endpointguard" `
      -PostgresDsn   "postgres://eg:eg@localhost:5432/endpointguard"
#>

param(
    [int]$GrpcPort = 4443,
    [int]$HttpPort = 8080,
    [string]$InstallDir = "C:\Program Files\EndpointGuard",
    [string]$CertDir = "C:\ProgramData\EndpointGuard\certs",
    [string]$ClickHouseDsn = "clickhouse://localhost:9000/endpointguard",
    [string]$PostgresDsn = "postgres://eg:eg@localhost:5432/endpointguard",
    [string]$BinarySrc = "$PSScriptRoot\..\server\eg-server.exe"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Run this script from an elevated (Administrator) PowerShell."
        exit 1
    }
}
Assert-Admin

if (-not (Test-Path $BinarySrc)) {
    Write-Error "Server binary not found at $BinarySrc — build it first:`n  cd server; go build -o eg-server.exe .\cmd\server"
    exit 1
}

Write-Host "== Installing binary and certs ==" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $CertDir | Out-Null
Copy-Item $BinarySrc "$InstallDir\eg-server.exe" -Force

if (-not (Test-Path "$CertDir\server.crt")) {
    Write-Host "  (!) No server cert found in $CertDir — copy your TLS cert/key" -ForegroundColor Yellow
    Write-Host "      and client-signing CA there before starting the service:" -ForegroundColor Yellow
    Write-Host "        $CertDir\server.crt  $CertDir\server.key  $CertDir\client-ca.crt" -ForegroundColor Yellow
}

Write-Host "== Writing config to the registry =="  -ForegroundColor Cyan
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EndpointGuardServer\Parameters"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_LISTEN"        -Value ":$GrpcPort"               -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_HTTP_ADDR"      -Value ":$HttpPort"               -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_TLS_CERT"       -Value "$CertDir\server.crt"      -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_TLS_KEY"        -Value "$CertDir\server.key"      -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_CLIENT_CA"      -Value "$CertDir\client-ca.crt"   -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_CLICKHOUSE_DSN" -Value $ClickHouseDsn             -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "EG_POSTGRES_DSN"   -Value $PostgresDsn               -PropertyType String -Force | Out-Null

Write-Host "== Writing launcher wrapper ==" -ForegroundColor Cyan
$Launcher = @'
# eg-server-launch.ps1 — reads EndpointGuard's registry Parameters and
# re-execs the real server binary with them as environment variables, since
# Windows services do not expose a Parameters key as env vars on their own.
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EndpointGuardServer\Parameters"
$Params  = Get-ItemProperty -Path $RegPath
foreach ($name in @("EG_LISTEN","EG_HTTP_ADDR","EG_TLS_CERT","EG_TLS_KEY","EG_CLIENT_CA","EG_CLICKHOUSE_DSN","EG_POSTGRES_DSN")) {
    $val = $Params.$name
    if ($val) { [Environment]::SetEnvironmentVariable($name, $val, "Process") }
}
& "$PSScriptRoot\eg-server.exe"
'@
Set-Content -Path "$InstallDir\eg-server-launch.ps1" -Value $Launcher -Encoding UTF8

Write-Host "== Registering Windows Service ==" -ForegroundColor Cyan
$ExistingSvc = Get-Service -Name "EndpointGuardServer" -ErrorAction SilentlyContinue
if ($ExistingSvc) {
    Write-Host "  Service already exists — stopping before reinstall."
    Stop-Service -Name "EndpointGuardServer" -Force -ErrorAction SilentlyContinue
    sc.exe delete "EndpointGuardServer" | Out-Null
    Start-Sleep -Seconds 1
}

$BinPath = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\eg-server-launch.ps1`""
sc.exe create "EndpointGuardServer" binPath= $BinPath start= auto DisplayName= "EndpointGuard Control Server" | Out-Null
sc.exe description "EndpointGuardServer" "EndpointGuard EDR/RMM control server — agent tunnel + dashboard API." | Out-Null
sc.exe failure "EndpointGuardServer" reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

Write-Host ""
Write-Host "Installed. Review certs in $CertDir, then:" -ForegroundColor Green
Write-Host "  Start-Service EndpointGuardServer"
Write-Host "  Get-EventLog -LogName Application -Source EndpointGuardServer -Newest 20   # or check the service's own log output"
Write-Host ""
Write-Host "First start prints a one-time admin dashboard password — the service"
Write-Host "runs with its console output captured; if you don't see it, run"
Write-Host "  & `"$InstallDir\eg-server-launch.ps1`"   manually once in a terminal to view it."
Write-Host ""
Write-Host "Dashboard/API will be reachable at: http://<this-machine-IP>:$HttpPort" -ForegroundColor Green
Write-Host "Agents connect to:                  <this-machine-IP-or-hostname>:$GrpcPort" -ForegroundColor Green
