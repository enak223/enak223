<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-26
    Last Modified   : 2025-08-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000505

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AU-000505.ps1
#>

# Ensure script runs as admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit
}

# Desired lockout duration in minutes (15 or greater; 0 also acceptable)
$DesiredDuration = 15

# Get current setting using Net Accounts
$currentSettings = net accounts
Write-Output "Current Account Lockout Duration:"
$currentSettings | Select-String "Lockout duration"

# Apply new setting
# 0 = require admin to unlock (also compliant)
# Otherwise, specify 15 or more minutes
if ($DesiredDuration -eq 0) {
    Write-Output "Setting Account Lockout Duration to require admin unlock (0)..."
    net accounts /lockoutduration:0
} else {
    Write-Output "Setting Account Lockout Duration to $DesiredDuration minutes..."
    net accounts /lockoutduration:$DesiredDuration
}

# Verify after change
Write-Output "`nUpdated Account Lockout Duration:"
(net accounts) | Select-String "Lockout duration"
