<#
.SYNOPSIS
    This PowerShell script prevents the WinRM service from storing RunAs credentials.

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-26
    Last Modified   : 2026-11-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000355

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell window (Run as Administrator).
    Example syntax:
    PS C:\> .\WN10-CC-000355.ps1
#>

<#
.SYNOPSIS
  Remediation script for Windows 10 STIG:
  WN10-CC-000355 (WinRM must not store RunAs credentials)
#>

Write-Host "🔧 Applying STIG WN10-CC-000355..." -ForegroundColor Cyan

# Registry path and value
$regPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "DisableRunAs"
$desiredValue = 1

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Host "Creating missing registry key: $regPath" -ForegroundColor Yellow
    New-Item -Path $regPath -Force | Out-Null
}

# Get current value (if exists)
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Apply setting if not compliant
if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type DWord
    Write-Host "✔ WinRM configured to disallow RunAs credential storage." -ForegroundColor Green
} else {
    Write-Host "✔ WinRM RunAs credential storage already disabled." -ForegroundColor Green
}

# Verification
$verify = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
Write-Host "`n📋 Verification Result:" -ForegroundColor Cyan
Write-Host " DisableRunAs : $verify (expected: 1)"

Write-Host "`n✅ STIG WN10-CC-000355 Remediation Complete!" -ForegroundColor Cyan
