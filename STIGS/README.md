# Programmatic Vulnerability Remediations (PowerShell)

PowerShell scripts that remediate DISA STIG findings and Tenable vulnerability findings on Windows hosts. Each script applies one control, then verifies the result.

## STIG Remediations (Windows 10)

| Script | STIG ID | What it enforces | Method |
|---|---|---|---|
| [WN10-AC-000005.ps1](WN10-AC-000005.ps1) | WN10-AC-000005 | Account lockout duration ≥ 15 minutes (or 0 = admin unlock) | `net accounts` |
| [WN10-AC-000020.ps1](WN10-AC-000020.ps1) | WN10-AC-000020 | Password history = 24 passwords remembered | `secedit` |
| [WN10-AC-000030.ps1](WN10-AC-000030.ps1) | WN10-AC-000030 | Minimum password age ≥ 1 day | `net accounts` |
| [WN10-AC-000035.ps1](WN10-AC-000035.ps1) | WN10-AC-000035 | Minimum password length ≥ 14 characters | `net accounts` |
| [WN10-AC-000040.ps1](WN10-AC-000040.ps1) | WN10-AC-000040 | Password complexity enabled | `secedit` |
| [WN10-AC-000045.ps1](WN10-AC-000045.ps1) | WN10-AC-000045 | Reversible password encryption disabled | `secedit` |
| [WN10-AU-000010.ps1](WN10-AU-000010.ps1) | WN10-AU-000010 | Audit Credential Validation (success and failure) | `auditpol` + registry |
| [WN10-AU-000500.ps1](WN10-AU-000500.ps1) | WN10-AU-000500 | Application event log ≥ 32,768 KB | Registry (policy key) |
| [WN10-AU-000505_WN10-AU-000510.ps1](WN10-AU-000505_WN10-AU-000510.ps1) | WN10-AU-000505, WN10-AU-000510 | Security event log ≥ 1,024,000 KB; System event log ≥ 32,768 KB | Registry (policy keys) |
| [WN10-CC-000007.ps1](WN10-CC-000007.ps1) | WN10-CC-000007 | Camera access denied | Registry |
| [WN10-CC-000355.ps1](WN10-CC-000355.ps1) | WN10-CC-000355 | WinRM service does not store RunAs credentials | Registry (policy key) |

## Vulnerability Remediations (Tenable findings)

| Script | Findings | What it does |
|---|---|---|
| [Remediate-ThirdPartySoftware.ps1](Remediate-ThirdPartySoftware.ps1) | Firefox, Oracle Java SE 8u202, Wireshark 2.2.1, MSXML 4.0 | Upgrades Firefox; removes the end-of-life software |
| [Disable-LegacyTLS.ps1](Disable-LegacyTLS.ps1) | Plugins 104743, 157288, 10114 | Disables TLS 1.0/1.1 (keeps TLS 1.2) and blocks inbound ICMP timestamp requests |

## Usage

1. Open PowerShell **as Administrator** on the target machine.
2. Run the script, e.g. `.\WN10-AU-000500.ps1`. Each script prints the value it set so you can confirm it.
3. Re-scan (Tenable / CIS or STIG audit) to verify the finding is closed.

If a script runs but the scan still fails, check for a **domain GPO** overriding the local setting, and confirm whether the check reads the **policy** registry path (`HKLM\SOFTWARE\Policies\...`) or the local one. That gap is documented in the [Vulnerability Management Program](https://github.com/enak223/vulnerability-management-program) project.

> Test in a lab or non-production environment first. Several settings (password policy, lockout, TLS) can affect users and legacy systems.

## Author

**Eliezer Fuentes**: [LinkedIn](https://linkedin.com/in/eliezerfuentes) · [GitHub](https://github.com/enak223)
