<#
.SYNOPSIS
    This PowerShell script remediates the third-party software findings from a Tenable scan of a
    Windows 11 host: it upgrades Mozilla Firefox and removes Oracle Java SE 8u202, Wireshark 2.2.1
    and MSXML 4.0 (133 of the scan's 138 vulnerability plugins, CVSS3 up to 10.0).

.NOTES
    Author          : Eliezer Fuentes
    LinkedIn        : linkedin.com/in/eliezerfuentes/
    GitHub          : github.com/enak223/
    Date Created    : 2026-11-22
    Last Modified   : 2026-11-22
    Version         : 1.0
    CVEs            : Multiple (see Plugin IDs)
    Plugin IDs      : Firefox (80 plugins, e.g. 378432, 372627, 328773), Oracle Java SE (35, e.g. 372932, 234624),
                      Wireshark (17, e.g. 56710, 311411), MSXML 4.0 (62758)
    STIG-ID         : N/A

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell window, then restart and re-scan.
    Example syntax:
    PS C:\> .\Remediate-ThirdPartySoftware.ps1
#>

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates the third-party software findings from the Tenable scan of a Windows 11 host.

.DESCRIPTION
    Four outdated or end-of-life products account for 133 of the 138 vulnerability plugins:

      Product              Installed      Plugins  Max CVSS3  Action
      -------------------  -------------  -------  ---------  ---------------------------
      Mozilla Firefox      110.0          80       10.0       Upgrade to latest release
      Oracle Java SE 8     8u202          35       9.8        Uninstall
      Wireshark            2.2.1 (EOL)    17       10.0       Uninstall
      MSXML 4.0            4.30.2117 EOL  1        10.0       Uninstall / unregister

    Every action is logged to C:\ProgramData\Remediation\. Restart and re-scan afterwards.

.NOTES
    Run in an elevated (admin) PowerShell window.
    Take a VM snapshot first if you want an easy rollback.
#>

$ErrorActionPreference = 'Stop'

# PowerShell 5.1 defaults can exclude TLS 1.2, which download.mozilla.org requires
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogDir  = "$env:ProgramData\Remediation"
$LogFile = Join-Path $LogDir "ThirdParty_$(Get-Date -Format yyyyMMdd_HHmmss).log"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
Start-Transcript -Path $LogFile | Out-Null

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Returns installed programs whose display name matches a wildcard pattern (64-bit and 32-bit registry views)
function Get-InstalledApp {
    param([Parameter(Mandatory)][string]$NamePattern)
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like $NamePattern } |
        Select-Object DisplayName, DisplayVersion, PSChildName, UninstallString
}

# Silently uninstalls every program matching the pattern (MSI by product code, otherwise NSIS-style /S)
function Uninstall-App {
    param([Parameter(Mandatory)][string]$NamePattern)

    $apps = @(Get-InstalledApp -NamePattern $NamePattern)
    if ($apps.Count -eq 0) {
        Write-Host "[skip]   Nothing matching '$NamePattern' is installed."
        return
    }

    foreach ($app in $apps) {
        Write-Host "[remove] $($app.DisplayName) $($app.DisplayVersion)"

        if ($app.PSChildName -match '^\{[0-9A-Fa-f\-]{36}\}$') {
            # MSI product: the registry key name is the product code
            $proc = Start-Process -FilePath 'msiexec.exe' `
                -ArgumentList "/x $($app.PSChildName) /qn /norestart" -Wait -PassThru
            Write-Host "         msiexec exit code: $($proc.ExitCode) (0 or 3010 = success)"
        }
        elseif ($app.UninstallString) {
            # EXE uninstaller (e.g. Wireshark's NSIS uninstall.exe): extract the path and run it with /S
            $exe = if ($app.UninstallString -match '^"([^"]+)"') { $Matches[1] }
                   else { ($app.UninstallString -split ' ')[0] }
            Start-Process -FilePath $exe -ArgumentList '/S' -Wait | Out-Null

            # NSIS uninstallers re-launch themselves from %TEMP%, so wait until the entry is gone
            $deadline = (Get-Date).AddMinutes(3)
            while ((Get-InstalledApp -NamePattern $app.DisplayName) -and ((Get-Date) -lt $deadline)) {
                Start-Sleep -Seconds 5
            }
        }
        else {
            Write-Warning "         No uninstall command found for $($app.DisplayName). Remove it manually."
        }

        if (Get-InstalledApp -NamePattern $app.DisplayName) {
            Write-Warning "         $($app.DisplayName) still appears installed. Check Settings > Apps."
        } else {
            Write-Host "         Removed."
        }
    }
}

# ---------------------------------------------------------------------------
# 1. Mozilla Firefox 110.0 -> latest (80 plugins, CVSS3 up to 10.0)
# ---------------------------------------------------------------------------
Write-Host "`n=== Mozilla Firefox ===" -ForegroundColor Cyan
$ffExe = 'C:\Program Files\Mozilla Firefox\firefox.exe'

if (Test-Path $ffExe) {
    $before = (Get-Item $ffExe).VersionInfo.ProductVersion
    Write-Host "Installed version: $before"

    $ffUrl       = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'
    $ffInstaller = Join-Path $env:TEMP 'FirefoxSetup.exe'

    try {
        Invoke-WebRequest -Uri $ffUrl -OutFile $ffInstaller -UseBasicParsing

        # Only run the installer if it is validly signed by Mozilla
        $sig = Get-AuthenticodeSignature -FilePath $ffInstaller
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Mozilla Corporation') {
            throw "Installer signature check failed: $($sig.Status) / $($sig.SignerCertificate.Subject)"
        }

        # Firefox must be closed for an in-place upgrade
        Get-Process -Name firefox -ErrorAction SilentlyContinue | Stop-Process -Force

        Start-Process -FilePath $ffInstaller -ArgumentList '/S' -Wait
        $after = (Get-Item $ffExe).VersionInfo.ProductVersion
        Write-Host "Upgraded: $before -> $after"
    }
    catch {
        Write-Warning "Firefox upgrade failed: $($_.Exception.Message)"
        Write-Warning "If the download is blocked, uninstall Firefox instead: Uninstall-App 'Mozilla Firefox*'"
    }
    finally {
        Remove-Item $ffInstaller -Force -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host "[skip]   Firefox not found at $ffExe"
}

# ---------------------------------------------------------------------------
# 2. Oracle Java SE 8 Update 202 -> uninstall (35 plugins, CVSS3 up to 9.8)
#    8u202 is the last free Oracle Java 8 build; newer builds need a paid licence.
#    If an app needs Java, install a free OpenJDK build (e.g. Eclipse Temurin) afterwards.
# ---------------------------------------------------------------------------
Write-Host "`n=== Oracle Java SE ===" -ForegroundColor Cyan
Uninstall-App -NamePattern 'Java 8 Update*'
Uninstall-App -NamePattern 'Java(TM) SE*'

# ---------------------------------------------------------------------------
# 3. Wireshark 2.2.1 -> uninstall (17 plugins, branch end-of-life since 2018)
# ---------------------------------------------------------------------------
Write-Host "`n=== Wireshark ===" -ForegroundColor Cyan
Uninstall-App -NamePattern 'Wireshark*'
Uninstall-App -NamePattern 'WinPcap*'     # bundled capture driver, also unsupported

# ---------------------------------------------------------------------------
# 4. MSXML 4.0 -> uninstall / unregister (end-of-life since 2014)
# ---------------------------------------------------------------------------
Write-Host "`n=== MSXML 4.0 ===" -ForegroundColor Cyan
Uninstall-App -NamePattern 'MSXML 4.0*'

# If the DLL is still present (installed by an app, not as its own product), unregister and rename it
$msxml4 = 'C:\Windows\SysWOW64\msxml4.dll'
if (Test-Path $msxml4) {
    Write-Host "[remove] $msxml4 still present: unregistering and renaming"
    try {
        Start-Process -FilePath "$env:windir\SysWOW64\regsvr32.exe" -ArgumentList "/u /s `"$msxml4`"" -Wait
        Rename-Item -Path $msxml4 -NewName 'msxml4.dll.disabled'
        Write-Host "         Renamed to msxml4.dll.disabled (rename it back to undo)."
    }
    catch {
        Write-Warning "         Could not rename msxml4.dll: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n=== Remaining matches (should be empty except updated Firefox) ===" -ForegroundColor Cyan
Get-InstalledApp -NamePattern '*Firefox*'   | Format-Table DisplayName, DisplayVersion -AutoSize
Get-InstalledApp -NamePattern '*Java*'      | Format-Table DisplayName, DisplayVersion -AutoSize
Get-InstalledApp -NamePattern '*Wireshark*' | Format-Table DisplayName, DisplayVersion -AutoSize
Get-InstalledApp -NamePattern '*MSXML 4*'   | Format-Table DisplayName, DisplayVersion -AutoSize

Write-Host "`nDone. Log: $LogFile"
Write-Host "Restart the VM, then re-run the Tenable scan." -ForegroundColor Yellow
Stop-Transcript | Out-Null
