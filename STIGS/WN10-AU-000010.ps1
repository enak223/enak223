<#
.SYNOPSIS
    This PowerShell script enables auditing of Account Logon - Credential Validation (success and failure).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-26
    Last Modified   : 2026-11-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell window (Run as Administrator).
    Example syntax:
    PS C:\> .\WN10-AU-000010.ps1
#>

Write-Host "🔧 Applying STIG WN10-AU-000010..." -ForegroundColor Cyan

# Ensure "Audit: Force audit policy subcategory settings..." is enabled
$overrideKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$overrideName = "SCENoApplyLegacyAuditPolicy"
$overrideValue = 1

Write-Host "Checking 'Force subcategory settings override'..."
$currentValue = (Get-ItemProperty -Path $overrideKey -Name $overrideName -ErrorAction SilentlyContinue).$overrideName

if ($currentValue -ne $overrideValue) {
    Set-ItemProperty -Path $overrideKey -Name $overrideName -Value $overrideValue -Type DWord
    Write-Host "✔ Enabled policy override." -ForegroundColor Green
} else {
    Write-Host "✔ Policy override already enabled." -ForegroundColor Green
}

# Configure Credential Validation for Success and Failure
Write-Host "Configuring audit policy: Account Logon -> Credential Validation (Success and Failure)..."
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null

# Verification
Write-Host "`n📋 Verification Result:"
$auditResult = auditpol /get /subcategory:"Credential Validation"
$auditParsed = $auditResult | Select-String "Credential Validation"

if ($auditParsed -match "Success and Failure") {
    Write-Host "✅ Credential Validation is configured for Success and Failure." -ForegroundColor Green
} else {
    Write-Host "WARNING: ⚠️ Credential Validation auditing is NOT correctly configured." -ForegroundColor Yellow
    Write-Host "Current setting: $auditParsed"
    
    # Check for GPO override (detect if domain-joined and possible policy application)
    $domain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    if ($domain) {
        Write-Host "`n⚠️ System is domain-joined. Group Policy may be overriding local settings." -ForegroundColor Yellow
        Write-Host "Run: gpresult /h C:\gp.html and review Advanced Audit Policy settings."
    }
    Write-Host "Consider rebooting if the override key was just applied."
}

Write-Host "`n✔ STIG remediation attempt completed."
