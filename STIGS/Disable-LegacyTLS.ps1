<#
.SYNOPSIS
    This PowerShell script disables TLS 1.0 and TLS 1.1 system-wide (SCHANNEL), keeps TLS 1.2 enabled,
    and blocks inbound ICMP timestamp requests (CVE-1999-0524).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2026-11-22
    Last Modified   : 2026-11-22
    Version         : 1.0
    CVEs            : CVE-1999-0524
    Plugin IDs      : 104743, 157288, 10114
    STIG-ID         : N/A

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell window, then restart for the TLS change to take effect.
    Example syntax:
    PS C:\> .\Disable-LegacyTLS.ps1
#>

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disables TLS 1.0 and TLS 1.1 system-wide (SCHANNEL) and blocks ICMP timestamp requests.

.DESCRIPTION
    Remediates these findings from the Tenable scan of a Windows 11 host:

      Plugin  Finding                                        CVSS3  Port
      ------  ---------------------------------------------  -----  ----
      104743  TLS Version 1.0 Protocol Detection             6.5    3389
      157288  TLS Version 1.1 Deprecated Protocol            6.5    3389
      10114   ICMP Timestamp Request Remote Date Disclosure  4.0    -

    TLS 1.2 and 1.3 stay enabled, so RDP and Bastion keep working on Windows 11.
    The SCHANNEL change needs a RESTART to take effect.

    Not fixed here: plugins 51192 / 57582 (RDP self-signed certificate on 3389).
    Those need a CA-issued certificate; record them as a risk exception in the lab.

.NOTES
    Run in an elevated (admin) PowerShell window.
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Disable TLS 1.0 and TLS 1.1 for both server and client roles
#    Enabled = 0 turns the protocol off; DisabledByDefault = 1 stops apps opting in
# ---------------------------------------------------------------------------
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

foreach ($protocol in 'TLS 1.0', 'TLS 1.1') {
    foreach ($role in 'Server', 'Client') {
        $key = "$base\$protocol\$role"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name 'Enabled'           -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Host "[set] $protocol $role : Enabled=0, DisabledByDefault=1"
    }
}

# ---------------------------------------------------------------------------
# 2. Make sure TLS 1.2 is explicitly enabled (protects RDP after the change)
# ---------------------------------------------------------------------------
foreach ($role in 'Server', 'Client') {
    $key = "$base\TLS 1.2\$role"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Enabled'           -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name 'DisabledByDefault' -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Host "[set] TLS 1.2 $role : Enabled=1, DisabledByDefault=0"
}

# ---------------------------------------------------------------------------
# 3. Block inbound ICMP timestamp requests (type 13), CVE-1999-0524
# ---------------------------------------------------------------------------
$ruleName = 'Block ICMP Timestamp Request'
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol ICMPv4 `
        -IcmpType 13 -Action Block | Out-Null
    Write-Host "[add] Firewall rule '$ruleName'"
} else {
    Write-Host "[skip] Firewall rule '$ruleName' already exists"
}

# A block rule does nothing while the firewall is off, so warn instead of turning it on blindly
$off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($off) {
    Write-Warning ("Windows Firewall is OFF for: {0}. The ICMP rule is not enforced until it is enabled." -f ($off.Name -join ', '))
    Write-Warning "Before enabling it, allow the Nessus scanner (SMB 445) so credentialed scans keep working."
}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
Write-Host "`n=== SCHANNEL protocol settings ===" -ForegroundColor Cyan
foreach ($protocol in 'TLS 1.0', 'TLS 1.1', 'TLS 1.2') {
    foreach ($role in 'Server', 'Client') {
        $p = Get-ItemProperty -Path "$base\$protocol\$role"
        '{0,-8} {1,-7} Enabled={2} DisabledByDefault={3}' -f $protocol, $role, $p.Enabled, $p.DisabledByDefault
    }
}

Write-Host "`nRestart the VM for the TLS change to take effect, then re-scan." -ForegroundColor Yellow
