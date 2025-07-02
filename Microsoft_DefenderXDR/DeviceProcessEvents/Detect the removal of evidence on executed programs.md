**Detect the removal of evidence on executed programs**

A typical technique used by ransomware operators is the deletion of Prefetch files, which track recently executed programs. By running commands like del C:\Windows\Prefetch\*.pf, attackers attempt to erase forensic traces of tools they’ve used.This behavior is aimed at hindering investigation and slowing down incident response.

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_all ("del", "C:\\Windows\\Prefetch", ".pf")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName, ReportId
```
