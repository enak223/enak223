<#
.SYNOPSIS
    This PowerShell script sets the minimum password age to at least 1 day.

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-25
    Last Modified   : 2026-11-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell window (Run as Administrator).
    Example syntax:
    PS C:\> .\WN10-AC-000030.ps1
#>

# Ensure script runs with Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit
}

# Desired minimum password age in days (must be >= 1 for compliance)
$DesiredMinPasswordAge = 1

Write-Output "Current password policy settings:"
net accounts

Write-Output "`nConfiguring Minimum Password Age to $DesiredMinPasswordAge day(s)..."
net accounts /minpwage:$DesiredMinPasswordAge

Write-Output "`nUpdated password policy settings:"
net accounts
