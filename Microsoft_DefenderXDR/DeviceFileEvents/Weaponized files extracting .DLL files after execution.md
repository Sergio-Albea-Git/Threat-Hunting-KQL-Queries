**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1203 | Exploitation for Client Execution |

**Author:** Sergio Albea (23/04/2025)

---

**Weaponized files extracting .DLL files after execution**

**Description:** When Weaponize files such as Word documents are opened, they can immediately extracts a disguised DLL file into the system’s temporary folder while simultaneously exploiting the Equation Editor vulnerability to execute the extracted file.The following query can help to identify when either a Word or another unusual file (I am whitelisting zip ones) extract a DLL file once is executed.

```
DeviceFileEvents
| extend FileOriginReferrerUrl_ext = extract(@"[^\\]+$", 0, FileOriginReferrerUrl)
| where isnotempty( FileOriginReferrerUrl)
| join kind=inner ( DeviceEvents) on $left.InitiatingProcessUniqueId == $right.InitiatingProcessUniqueId
| extend FilesExtension = extract(@"\.([a-zA-Z0-9]+)$", 1, FileName)
| extend OriginalFileExtension = extract(@"\.([a-zA-Z0-9]+)$", 1, FileOriginReferrerUrl_ext)
| extend Source_Type = case(FileOriginReferrerUrl startswith "http","🌎 Web","📂 File")
| where OriginalFileExtension !in ("zip","7z") and FilesExtension endswith ".dll"
| summarize total_Files= dcount(FileName), Files_after_execution= strcat("🗂️ ",make_set(FileName)),make_set(FilesExtension),make_set(ActionType),make_set(FolderPath),SHA256_Group=make_set(SHA2561) by InitiatingProcessUniqueId,AccountUpn = strcat("👩🏻💻🧑🏾💻",InitiatingProcessAccountUpn), Device = strcat("💻 ",DeviceName), FileOriginReferrerUrl,Source_Type, OriginalFile=strcat("🚩 ",FileOriginReferrerUrl_ext), OriginalFileExtension, ReportId, TimeGenerated, Timestamp, DeviceId
```
