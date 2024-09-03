**Non-supported Agent version required for the Contain User action by Attack Disruption**

**Description:** The following query checks if the devices have the minimum sense agent version(v10.8470) required for the Contain User action trigger by Microsoft DefenderXDR Attack disruption.
```
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey contains "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection" 
| extend version_s = replace(@"[.]", "", InitiatingProcessVersionInfoProductVersion)
| extend FirstFiveChars = substring(version_s, 0, 6)
| extend FirstFiveChars = toint(FirstFiveChars)
| where FirstFiveChars < 108470
| summarize by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessVersionInfoProductVersion
```
