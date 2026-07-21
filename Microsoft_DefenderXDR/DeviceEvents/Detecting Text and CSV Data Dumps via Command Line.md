**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1005 | Data from Local System |

**Author:** Sergio Albea (05/06/2026)

---

**Detecting Text and CSV Data Dumps via Command Line**

This KQL Query detects when a device exports data to commonly used file formats like .csv or .txt.
This kind of behavior is often seen during the early stages of ransomware activity, where attackers collect internal information before exfiltrating it.
If you want to detect specific commands, you can use filters like:

 ➡️ | 𝘸𝘩𝘦𝘳𝘦 𝘊𝘰𝘮𝘮𝘢𝘯𝘥 𝘴𝘵𝘢𝘳𝘵𝘴𝘸𝘪𝘵𝘩 "𝘎𝘦𝘵-𝘈𝘋𝘊𝘰𝘮𝘱𝘶𝘵𝘦𝘳 -𝘍𝘪𝘭𝘵𝘦𝘳 *"

 ➡️ | 𝘸𝘩𝘦𝘳𝘦 𝘊𝘰𝘮𝘮𝘢𝘯𝘥 𝘴𝘵𝘢𝘳𝘵𝘴𝘸𝘪𝘵𝘩 "𝘎𝘦𝘵-𝘈𝘋𝘜𝘴𝘦𝘳 -𝘍𝘪𝘭𝘵𝘦𝘳 *"
```
DeviceEvents
| where isnotempty(AdditionalFields) 
| extend Command = tostring(parse_json(AdditionalFields).Command)
// search for commands exporting data into .txt or .csv format
| where Command endswith ".txt" or Command endswith ".csv"
// excluding known cases
| where Command !startswith "Start-Process"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine, Command, InitiatingProcessAccountName, InitiatingProcessAccountUpn, ProcessRemoteSessionDeviceName, ReportId
```
