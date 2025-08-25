<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-25
    Last Modified   : 2025-08-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000045

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# Requires: PowerShell 5.1 (native on Windows 10). Run as Administrator.

# --- Guardrails: Ensure script runs as Administrator ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# --- Paths ---
$inf  = Join-Path $env:TEMP "secpol.inf"
$sdb  = Join-Path $env:TEMP "secpol.sdb"
$verifyInf = Join-Path $env:TEMP "verify_secpol.inf"

# --- Export current Local Security Policy ---
secedit /export /cfg $inf | Out-Null
$lines = Get-Content $inf

# --- Ensure [System Access] exists and set ClearTextPassword = 0 (Disabled) ---
$saIndex = ($lines | Select-String '^\[System Access\]$').LineNumber
if (-not $saIndex) {
    $lines += ''
    $lines += '[System Access]'
    $saIndex = ($lines | Select-String '^\[System Access\]$').LineNumber
}

if ($lines -match '^ClearTextPassword\s*=') {
    $lines = $lines -replace '^ClearTextPassword\s*=\s*\d', 'ClearTextPassword = 0'
} else {
    $insertAt = $saIndex
    $before = $lines[0..$insertAt]
    $after  = $lines[($insertAt+1)..($lines.Count-1)]
    $lines  = $before + 'ClearTextPassword = 0' + $after
}

# Save updated template (Unicode encoding is safest for secedit)
$lines | Set-Content $inf -Encoding Unicode

# --- Apply updated policy ---
secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY | Out-Null

# --- Verify ---
secedit /export /cfg $verifyInf | Out-Null
$ver = (Get-Content $verifyInf | Select-String '^ClearTextPassword\s*=\s*(\d)').Matches.Groups[1].Value
if ($ver -eq '0') {
    Write-Output "✅ Reversible password encryption is DISABLED (ClearTextPassword = 0)."
} else {
    Write-Warning "⚠️ Verification shows ClearTextPassword = $ver (expected 0). A domain GPO may be overriding this."
}

# --- Cleanup ---
Remove-Item $inf,$sdb,$verifyInf -Force -ErrorAction SilentlyContinue
