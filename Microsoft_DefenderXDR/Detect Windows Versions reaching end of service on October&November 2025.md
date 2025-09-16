**Detect Windows Versions reaching end of service on October&November 2025**

This query helps you quickly see the number of affected devices or get a detailed list of machines still running versions that are approaching end of support:

Windows 10 & 11 version 22H2 → end of support on October 14, 2025

Windows 11 version 23H2 (Home & Pro) → end of support on November 11, 2025

```
DeviceInfo
| where Timestamp > ago(1d)
| extend OSaffected = strcat(OSDistribution, " ", OSVersionInfo)
 // filter by the affected OS distributions
| where OSaffected has "22H2" or OSaffected has "23h2"
| extend Windows10_22H2 = iff(OSaffected has "Windows10 22h2", "🚨 October 14,2025","")
| extend Windows11_22H2 = iff(OSaffected has "Windows11 22h2", "🚨 October 14,2025","")
| extend Windows11_23H2 = iff( OSaffected has "Windows11 23h2" and OSBuild == 22631,"November 11,2025 (⚠️ If are Home or Pro versions,if not 2026-11-10)","")
| summarize Total_Devices= dcount(DeviceId) by OSPlatform,OSaffected, Windows10_22H2,Windows11_22H2,Windows11_23H2
//| summarize by DeviceName, DeviceId, OSaffected, Windows10_22H2,Windows11_22H2,Windows11_23H2
| order by OSaffected
```
