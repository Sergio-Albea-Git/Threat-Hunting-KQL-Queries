**Detect suspicious actions to change Desktop Background**

One of the key behaviors often observed during ransomware attacks includes altering the desktop background. These actions are designed to ensure that all users on the infected machine are made aware of the compromise.
Fortunately, if your environment monitors for registry changes , you may be able to detect such activities promptly. This can enable quick response actions—such as alerting, isolating the device (using Detection Rules Actions), or initiating automated investigation.

Changing a device background manually, is kind of expected user behaviour if you are allowing it. However, modify the associated register keys via command line, can be a good indicator about a Ransomware activity. Both of following cases, are commonly abused by ransomware (e.g., Rhysida,BlackCat) to control or lock desktop wallpaper settings.
```
DeviceProcessEvents
| where ProcessCommandLine has_any (
 "reg delete \"HKCU\\Control Panel\\Desktop\"",
 "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\"",
 "NoChangingWallPaper"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId

```
