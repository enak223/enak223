<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-31
    Last Modified   : 2025-08-31
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000007

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000007.ps1 
#>

<#
.SYNOPSIS
  Remediation script for Windows 10 STIG:
  WN10-CC-000007 (Camera must be disabled or covered when not in use)
#>

# Ensure script runs as admin
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator." -ForegroundColor Red
    Exit 1
}

Write-Host "🔧 Applying STIG WN10-CC-000007..." -ForegroundColor Cyan

# Registry path and value
$regPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
$valueName = "Value"
$desiredValue = "Deny"

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Host "Creating missing registry key: $regPath" -ForegroundColor Yellow
    New-Item -Path $regPath -Force | Out-Null
}

# Get current value (if exists)
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Apply setting if not compliant
if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type String
    Write-Host "✔ Camera access disabled via registry." -ForegroundColor Green
} else {
    Write-Host "✔ Camera access already disabled." -ForegroundColor Green
}

# Verification
$verify = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Host "`n📋 Verification Result:" -ForegroundColor Cyan
Write-Host " Value : $verify (expected: Deny)"

Write-Host "`n✅ STIG WN10-CC-000007 Remediation Complete!" -ForegroundColor Cyan
