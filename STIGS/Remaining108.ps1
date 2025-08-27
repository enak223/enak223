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
    STIG-ID         : Remaining 108

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000010).ps1 
#>

<#
STIG Compliance
  - WN10-AU-000510: System event log size >= 32768 KB
  - WN10-AU-000505: Security event log size >= 1024000 KB

Notes:
- These settings live under the policy hive:
  HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\{System,Security}\MaxSize (REG_DWORD)
- If your org forwards audit logs directly to a server and treats these controls as N/A,
  skip with -AssumeForwarding switch (documentation with ISSO required).
#>

param(
    [switch]$AssumeForwarding
)

# --- Guardrails: Admin required ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "❌ Run this script as Administrator."
    exit 1
}

Write-Host "🔧 Applying STIGs WN10-AU-000510 (System) & WN10-AU-000505 (Security)..." -ForegroundColor Cyan

if ($AssumeForwarding) {
    Write-Warning "Audit records are assumed to be sent directly to an audit server. Marking these as N/A (per STIG). No changes applied."
    return
}

# --- Desired policy values (KB) ---
$targets = @(
    @{
        Name      = "System"
        Path      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
        ValueName = "MaxSize"
        Required  = 32768     # 32 MB
    },
    @{
        Name      = "Security"
        Path      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
        ValueName = "MaxSize"
        Required  = 1024000   # 1,024,000 KB (~1 GB)
    }
)

foreach ($t in $targets) {
    Write-Host "`n— Processing $($t.Name) log —" -ForegroundColor Yellow

    # Ensure policy key exists
    if (-not (Test-Path $t.Path)) {
        Write-Host "Creating policy path: $($t.Path)"
        New-Item -Path $t.Path -Force | Out-Null
    }

    # Get current value (KB)
    $current = (Get-ItemProperty -Path $t.Path -Name $t.ValueName -ErrorAction SilentlyContinue).$($t.ValueName)

    if (-not $current -or $current -lt $t.Required) {
        Write-Host "Setting $($t.Name) MaxSize to $($t.Required) KB..." -ForegroundColor Green
        New-ItemProperty -Path $t.Path -Name $t.ValueName -Value $t.Required -PropertyType DWord -Force | Out-Null
        Write-Host "✔ $($t.Name) MaxSize set to $($t.Required) KB."
    } else {
        Write-Host "✔ $($t.Name) MaxSize already compliant ($current KB)."
    }
}

# --- Verification (registry) ---
Write-Host "`n📋 Verification (policy registry):" -ForegroundColor Cyan
foreach ($t in $targets) {
    $val = (Get-ItemProperty -Path $t.Path -Name $t.ValueName -ErrorAction SilentlyContinue).$($t.ValueName)
    $status = if ($val -ge $t.Required) { "COMPLIANT" } else { "NON-COMPLIANT" }
    Write-Host ("{0,-10} MaxSize: {1,10} KB   Required: {2,10} KB   Status: {3}" -f $t.Name, $val, $t.Required, $status)
}

# Optional: show live channel max sizes (bytes) if available via wevtutil (informational)
Write-Host "`nℹ️ Live channel info (wevtutil) — may differ until policy refresh/restart:" -ForegroundColor DarkCyan
foreach ($chan in @("System","Security")) {
    try {
        $gl = wevtutil gl $chan 2>$null
        $max = ($gl | Where-Object { $_ -match 'maximumSize:' }) -replace '.*maximumSize:\s*',''
        if ($max) {
            Write-Host ("{0,-10} maximumSize: {1} bytes" -f $chan, $max.Trim())
        } else {
            Write-Host ("{0,-10} maximumSize: (unavailable)" -f $chan)
        }
    } catch {
        Write-Host ("{0,-10} maximumSize: (error reading)" -f $chan)
    }
}

Write-Host "`n✅ Completed STIG remediation for event-log sizes." -ForegroundColor Green
Write-Host "Tip: If a domain GPO manages these settings, it will override local policy. Run 'gpresult /h C:\gp.html' to review applied policies."
