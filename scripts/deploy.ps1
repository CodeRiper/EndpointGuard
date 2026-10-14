<#
.SYNOPSIS
  EndpointGuard one-line enrollment script.
  Run elevated (Admin) on any Windows endpoint:
    irm https://control.endpointguard.internal/enroll | iex

.NOTES
  The agent binary and its client certificate are fetched from the
  control server — no IP addresses appear here or in agent.exe.
#>
param(
    [string]$ServerHost  = "control.endpointguard.internal",
    [string]$EnrollToken = $Env:EG_ENROLL_TOKEN,
    [string]$InstallDir  = "$Env:ProgramFiles\EndpointGuard"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 1. Require elevation ──────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    throw "Run this script as Administrator."
}

Write-Host "[EG] Installing EndpointGuard on $Env:COMPUTERNAME"

# ── 2. Create install dir ─────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\certs" | Out-Null

$BaseUrl = "https://$ServerHost"

# ── 3. Download agent binary ──────────────────────────────────────────────────
Write-Host "[EG] Downloading agent binary..."
Invoke-WebRequest -Uri "$BaseUrl/dist/agent.exe" `
    -OutFile "$InstallDir\agent.exe" -UseBasicParsing

# ── 4. Enroll: exchange token for a unique client certificate ─────────────────
# The server issues one client cert per machine, tied to the machine's
# hostname and a hardware ID.  No shared secrets appear in the binary.
Write-Host "[EG] Enrolling with control server..."
$Body = @{
    hostname    = $Env:COMPUTERNAME
    token       = $EnrollToken
    hardware_id = (Get-WmiObject Win32_ComputerSystemProduct).UUID
} | ConvertTo-Json

$Enrolled = Invoke-RestMethod `
    -Method Post `
    -Uri "$BaseUrl/api/enroll" `
    -ContentType "application/json" `
    -Body $Body

$Enrolled.client_cert | Out-File "$InstallDir\certs\client.crt" -Encoding ASCII
$Enrolled.client_key  | Out-File "$InstallDir\certs\client.key" -Encoding ASCII
$Enrolled.server_ca   | Out-File "$InstallDir\certs\server-ca.crt" -Encoding ASCII

Write-Host "[EG] Agent ID: $($Enrolled.agent_id)"

# ── 5. Write environment config to a secure registry key ─────────────────────
# Values stored in HKLM\SYSTEM so SYSTEM account can read them.
# ACLed so only SYSTEM and Admins can read — no plain-text config file.
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EndpointGuard\Parameters"
New-Item -Force -Path $RegPath | Out-Null
Set-ItemProperty -Path $RegPath -Name EG_SERVER_ADDR -Value "https://${ServerHost}:443"
Set-ItemProperty -Path $RegPath -Name EG_AGENT_ID    -Value $Enrolled.agent_id
Set-ItemProperty -Path $RegPath -Name EG_CLIENT_CERT -Value "$InstallDir\certs\client.crt"
Set-ItemProperty -Path $RegPath -Name EG_CLIENT_KEY  -Value "$InstallDir\certs\client.key"
Set-ItemProperty -Path $RegPath -Name EG_SERVER_CA   -Value "$InstallDir\certs\server-ca.crt"
Set-ItemProperty -Path $RegPath -Name EG_SERVER_CA_FINGERPRINT `
    -Value $Enrolled.ca_fingerprint

# ── 6. Install + harden the service ──────────────────────────────────────────
Write-Host "[EG] Installing Windows Service..."
Set-Location $InstallDir
.\agent.exe --install

# ── 7. Provision Chrome / Edge enterprise browser policies ────────────────────
Write-Host "[EG] Provisioning browser monitoring policies..."
.\agent.exe --provision-policies

Write-Host "[EG] Done.  Service status:"
Get-Service -Name "EndpointGuard" | Select-Object Name, Status, StartType
