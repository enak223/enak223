<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-24
    Last Modified   : 2025-08-24
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000020.ps1
#>

# Ensure script runs as admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit
}

# Desired password history count
$DesiredHistory = 24

# Display current setting
Write-Output "Current Password Policy Settings:"
secedit /export /cfg C:\Windows\Temp\secpol.cfg
$currentHistory = (Get-Content C:\Windows\Temp\secpol.cfg | Select-String "PasswordHistorySize").ToString()
Write-Output "Before Change: $currentHistory"

# Update the policy file
(Get-Content C:\Windows\Temp\secpol.cfg) |
ForEach-Object {
    if ($_ -match "^PasswordHistorySize") {
        "PasswordHistorySize = $DesiredHistory"
    } else {
        $_
    }
} | Set-Content C:\Windows\Temp\secpol.cfg

# Apply the updated policy
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Clean up temp file
Remove-Item C:\Windows\Temp\secpol.cfg -Force

# Confirm the change
Write-Output "`nUpdated Password Policy Settings:"
secedit /export /cfg C:\Windows\Temp\verify.cfg
(Get-Content C:\Windows\Temp\verify.cfg | Select-String "PasswordHistorySize").ToString()
Remove-Item C:\Windows\Temp\verify.cfg -Force
