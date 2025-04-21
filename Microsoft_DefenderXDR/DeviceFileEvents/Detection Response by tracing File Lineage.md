**Detection Response by tracing File Lineage**

**Description:** This query groups all files by their originating file—such as a ZIP archive or from a Website—and includes all the files that were extracted from it. 
Among the benefits of Correlating File Events Using **InitiatingProcessUniqueId** field we can identify:

- Provides full visibility into all files related to a single action (e.g., ZIP extraction).
- Helps detect hidden or secondary malicious files that may not trigger alerts.
- Traces the origin of files—whether downloaded or extracted from another source.
- Strengthens root cause analysis and incident investigation.
- Enhances detection of multi-stage payloads or complex delivery methods.
- Reduces the risk of overlooking related threats during response.
- Builds context around suspicious activity for better decision-making.
- Improves threat hunting efficiency by revealing attack chains clearly.

```
DeviceFileEvents
| extend FileOriginReferrerUrl_ext = extract(@"[^\\]+$", 0, FileOriginReferrerUrl)
| where isnotempty( FileOriginReferrerUrl)
| join kind=inner ( DeviceEvents) on $left.InitiatingProcessUniqueId == $right.InitiatingProcessUniqueId
| extend FileExtension = extract(@"\.([a-zA-Z0-9]+)$", 1, FileName)
| extend Source_Type = case(FileOriginReferrerUrl startswith  "https://", "🌎 Web","📂 File")
| summarize total_Files= dcount(FileName), Files_after_execution= strcat("🗂️ ",make_set(FileName)),make_set(FileExtension),make_set(ActionType),make_set(FolderPath),SHA256_Group=make_set(SHA2561) by  InitiatingProcessUniqueId,AccountUpn = strcat("👩🏻💻🧑🏾💻",InitiatingProcessAccountUpn), Device = strcat("💻 ",DeviceName), FileOriginReferrerUrl,Source_Type, OriginalFile=strcat("🚩 ",FileOriginReferrerUrl_ext)
```
