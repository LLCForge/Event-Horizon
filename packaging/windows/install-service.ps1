#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Event Horizon as a Windows service.

.DESCRIPTION
    Copies event-horizon.exe to Program Files, prepares a data directory writable by
    the service account (NT AUTHORITY\LocalService), places the configuration in
    ProgramData, optionally stores secret environment variables for the service,
    and registers the service with "event-horizon service install".

.PARAMETER Binary
    Path to event-horizon.exe (defaults to the copy next to this script).

.PARAMETER Config
    TOML configuration to install. Existing configuration is never overwritten.

.PARAMETER EnvFile
    Optional KEY=value file with secrets (bot tokens, routing keys, ...). They
    are stored in the service's registry Environment value, which local
    administrators can read. Keep the host's administrator group small.

.EXAMPLE
    .\install-service.ps1 -Config .\event-horizon.toml -EnvFile .\event-horizon.env
#>
[CmdletBinding()]
param(
    [string]$Binary = (Join-Path $PSScriptRoot 'event-horizon.exe'),
    [Parameter(Mandatory = $true)][string]$Config,
    [string]$EnvFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'event-horizon'
$installDir = Join-Path $env:ProgramFiles 'LLCForge\event-horizon'
$dataDir = Join-Path $env:ProgramData 'LLCForge\event-horizon'
$configPath = Join-Path $dataDir 'event-horizon.toml'

if (-not (Test-Path -LiteralPath $Binary)) { throw "Binary not found: $Binary" }
if (-not (Test-Path -LiteralPath $Config)) { throw "Config not found: $Config" }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Service '$serviceName' already exists. Run 'event-horizon service uninstall' first."
}

New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null
Copy-Item -LiteralPath $Binary -Destination (Join-Path $installDir 'event-horizon.exe') -Force

if (Test-Path -LiteralPath $configPath) {
    Write-Host "Keeping existing configuration $configPath"
} else {
    Copy-Item -LiteralPath $Config -Destination $configPath
}

# Data dir: LocalService may modify; inherited Users access removed.
& icacls.exe $dataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'NT AUTHORITY\LocalService:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE" }

$exe = Join-Path $installDir 'event-horizon.exe'
& $exe service install --config $configPath
if ($LASTEXITCODE -ne 0) { throw "'event-horizon service install' failed with exit code $LASTEXITCODE" }

$envVars = @("STATE_DIRECTORY=$dataDir")
if ($EnvFile) {
    if (-not (Test-Path -LiteralPath $EnvFile)) { throw "EnvFile not found: $EnvFile" }
    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -notmatch '^[A-Za-z_][A-Za-z0-9_]*=') { throw "Invalid line in EnvFile (expected KEY=value): $t" }
        $envVars += $t
    }
}
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
New-ItemProperty -Path $key -Name 'Environment' -PropertyType MultiString -Value $envVars -Force | Out-Null

Start-Service -Name $serviceName
Get-Service -Name $serviceName | Format-Table -AutoSize Name, Status, StartType
Write-Host "To debug: Stop-Service $serviceName, then run '$exe run --config $configPath' in a console."
