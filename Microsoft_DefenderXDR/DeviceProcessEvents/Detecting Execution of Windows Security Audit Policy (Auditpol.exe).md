**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1562.002 | Impair Defenses: Disable Windows Event Logging |

**Author:** Sergio Albea (05/06/2026)

---

**Detecting Execution of Windows Security Audit Policy (Auditpol.exe)**

Monitoring the execution of auditpol.exe can be crutial to detect first-stage of a real attack because they will be shown as previous steps to obfuscate the next execution such a ransomware

```
DeviceProcessEvents
| where AccountName !has "system" and FileName has "auditpol.exe"
| summarize by Timestamp,DeviceName,DeviceId,FileName,AccountDomain,InitiatingProcessAccountName,AccountName, ProcessCommandLine, ReportId
```
