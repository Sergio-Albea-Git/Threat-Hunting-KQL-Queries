**Detect TLS validation bypass via PowerShell**

PowerShell disabling TLS validation before downloading the payload, it’s a small step, but a very useful one from a detection point of view.
Just reading about a fake Boeing RFQ was enough to trigger a full attack chain — starting from a DOCX and moving through RTF, JavaScript, PowerShell and even a full Python runtime, ending with Cobalt Strike running in memory.
Nothing particularly new in terms of techniques, but the way everything is chained together makes it effective and easy to miss. It relies on tools and formats we see daily.
Being focus on catch the IoA Pattern, I created the KQL Detection below. 

```
DeviceProcessEvents 
| where Timestamp > ago(7d) 
| where FileName in~ ("powershell.exe","pwsh.exe") 
| where ProcessCommandLine has_any ("ServerCertificateValidationCallback","TrustAllCertsPolicy","SkipCertificateCheck","CertificatePolicy") 
| project Timestamp, DeviceName,DeviceId, AccountName, FileName, ProcessCommandLine , ReportId
```
