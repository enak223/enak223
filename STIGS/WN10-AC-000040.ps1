<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2025-08-25
    Last Modified   : 2025-08-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000040

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000040.ps1
#>

# Ensure script runs as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit
}

# Paths for temp files
$tempInf = "$env:TEMP\secpol.inf"
$tempSdb = "$env:TEMP\secpol.sdb"

# Export current security policy
secedit /export /cfg $tempInf > $null

# Read policy file
$secpol = Get-Content $tempInf

# Modify or add PasswordComplexity setting (1 = Enabled, 0 = Disabled)
if ($secpol -match "PasswordComplexity") {
    $secpol = $secpol -replace "PasswordComplexity = \d", "PasswordComplexity = 1"
} else {
    $index = ($secpol | Select-String "^\[System Access\]").LineNumber
    $secpol = $secpol[0..$index] + "PasswordComplexity = 1" + $secpol[($index+1)..($secpol.Length-1)]
}

# Save updated policy back
$secpol | Set-Content $tempInf -Encoding Unicode

# Apply updated security policy
secedit /configure /db $tempSdb /cfg $tempInf /areas SECURITYPOLICY > $null

# Clean up
Remove-Item $tempInf,$tempSdb -Force

Write-Output "✅ Password Complexity has been ENABLED (STIG WN10-AC-000040)."
