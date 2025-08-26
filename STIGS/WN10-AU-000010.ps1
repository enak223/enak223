<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-26
    Last Modified   : 2025-08-26
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
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

<#
.STIG: WN10-AU-000010
.Description: Configure system to audit Account Logon -> Credential Validation (Success)
#>

Write-Host "🔧 Applying STIG WN10-AU-000010..." -ForegroundColor Cyan

# Ensure "Force audit policy subcategory settings to override category settings" is enabled
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaName = "SCENoApplyLegacyAuditPolicy"
$lsaValue = 1

Write-Host "Checking 'Force subcategory settings override'..." -ForegroundColor Yellow
$currentValue = (Get-ItemProperty -Path $lsaPath -Name $lsaName -ErrorAction SilentlyContinue).$lsaName
if ($currentValue -ne $lsaValue) {
    Write-Host "Enabling 'Force subcategory settings override'..." -ForegroundColor Green
    New-ItemProperty -Path $lsaPath -Name $lsaName -Value $lsaValue -PropertyType DWord -Force | Out-Null
    Write-Host "✔ Policy override enabled." -ForegroundColor Green
} else {
    Write-Host "✔ Policy override already enabled." -ForegroundColor Green
}

# Configure audit policy for Credential Validation -> Success
Write-Host "Configuring audit policy: Account Logon -> Credential Validation (Success)..." -ForegroundColor Yellow
auditpol /set /subcategory:"Credential Validation" /success:enable | Out-Null

# Verification
Write-Host "`n📋 Verification Result:" -ForegroundColor Cyan
$result = auditpol /get /subcategory:"Credential Validation"
Write-Host $result

if ($result -match "Success\s+Enabled") {
    Write-Host "`n✅ Credential Validation success auditing is ENABLED." -ForegroundColor Green
} else {
    Write-Host "`nWARNING: ⚠️ Credential Validation success auditing is NOT enabled." -ForegroundColor Red
    Write-Host "Check if domain GPO is overriding or if the system requires a reboot." -ForegroundColor Yellow
}
