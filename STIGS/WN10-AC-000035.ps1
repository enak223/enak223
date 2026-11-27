<#
.SYNOPSIS
    This PowerShell script sets the minimum password length to 14 characters.

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-25
    Last Modified   : 2026-11-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell window (Run as Administrator).
    Example syntax:
    PS C:\> .\WN10-AC-000035.ps1
#>

# Ensure script runs with Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit
}

# Desired minimum password length (STIG requires at least 14)
$DesiredMinPasswordLength = 14

Write-Output "Current password policy settings:"
net accounts

Write-Output "`nConfiguring Minimum Password Length to $DesiredMinPasswordLength characters..."
net accounts /minpwlen:$DesiredMinPasswordLength

Write-Output "`nUpdated password policy settings:"
net accounts
