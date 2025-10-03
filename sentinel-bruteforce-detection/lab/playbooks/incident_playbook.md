# Incident Playbook — Brute Force Detection (NIST 800-61)

## Preparation
- Roles: Investigator, Remediator, Evidence Custodian
- Tools: Microsoft Sentinel, Defender for Endpoint, Azure Portal, Log Analytics

## Detection & Analysis
1. Validate alert and query results.
2. Identify RemoteIP(s), DeviceName(s), Account(s).
3. Enrich IPs: geo, ASN, internal? (note: do not perform intrusive scans).
4. Check for successful Logon events for same IP+device+account (use device_logon_success_check.kql).

## Containment
- Temporarily restrict NSG to only admin IPs / block offending IPs.
- Isolate VM if suspicious activity escalates.

## Eradication & Recovery
- Ensure no persistent backdoor; run AV/EDR scan (Defender).
- Reset compromised credentials, rotate secrets if any.
- Re-enable normal network after validation.

## Post-Incident
- Document timeline, root cause, lessons learned.
- Propose Azure Policy to enforce NSG lockdown for new VMs.
