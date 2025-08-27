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
    STIG-ID         : WN10-AU-000510 & WN10-AU-000505

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AU-000510 & WN10-AU-000505.ps1
#>

<#
.STIG Compliance Script
WN10-AU-000510 - System Event Log size must be >= 32768 KB
WN10-AU-000505 - Security Event Log size must be >= 1024000 KB
#>

Write-Host "🔧 Applying STIGs WN10-AU-000510 & WN10-AU-000505..." -ForegroundColor Cyan

# Registry Paths and Desired Values
$logConfigs = @(
    @{
        Name       = "System Log"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
        ValueName  = "MaxSize"
        DesiredKB  = 32768  # 32 MB
    },
    @{
        Name       = "Security Log"
        Path       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
        ValueName  = "MaxSize"
        DesiredKB  = 1024000  # 1,024,000 KB (1 GB)
    }
)

foreach ($config in $logConfigs) {
    Write-Host "`nProcessing: $($config.Name)" -ForegroundColor Yellow

    # Create registry path if it does not exist
    if (-not (Test-Path $config.Path)) {
        Write-Host "Creating registry path: $($config.Path)" -ForegroundColor Yellow
        New-Item -Path $config.Path -Force | Out-Null
    }

    # Get current value
    $currentValue = (Get-ItemProperty -Path $config.Path -Name $config.ValueName -ErrorAction SilentlyContinue).$($config.ValueName)

    if (-not $currentValue -or $currentValue -lt $config.DesiredKB) {
        Write-Host "Setting $($config.Name) MaxSize to $($config.DesiredKB) KB..." -ForegroundColor Green
        New-ItemProperty -Path $config.Path -Name $config.ValueName -Value $config.DesiredKB -PropertyType DWord -Force | Out-Null
        Write-Host "✔ $($config.Name) MaxSize set to $($config.DesiredKB) KB." -ForegroundColor Green
    } else {
        Write-Host "✔ $($config.Name) MaxSize ($currentValue KB) meets or exceeds requirement." -ForegroundColor Green
    }
}

# Verification Output
Write-Host "`n📋 Verification Result:" -ForegroundColor Cyan
foreach ($config in $logConfigs) {
    $value = (Get-ItemProperty -Path $config.Path -Name $config.ValueName -ErrorAction SilentlyContinue).$($config.ValueName)
    Write-Host "$($config.Name) Log MaxSize: $value KB"
}
