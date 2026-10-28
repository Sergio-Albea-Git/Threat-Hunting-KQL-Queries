**MITRE ATT&CK Technique(s)**

**Author:** Sergio Albea (23/10/2026)

---

**DPHP2Shell: Review PHP Versions selected in our Applications.md**

Further than have the PHP software updated with the supported versions and take actions over the Exposed Devices,having the latest PHP version installed doesn't mean your web applications are actually using it. I would recommend a double check over IIS, Apache or other process that could be executing old PHP Versions even if the server has installed the newest ones

let InternetFacingDevices =     DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, IsInternetFacing) by DeviceId
| project DeviceId, IsInternetFacing; let LatestInstalledPHP =     DeviceTvmSoftwareInventory  | where SoftwareName =~ "php"
| extend VersionParts = split(SoftwareVersion, ".")
| extend Major = toint(VersionParts[0]), Minor = toint(VersionParts[1]), Patch = toint(VersionParts[2])
| where isnotnull(Major) and isnotnull(Minor) | extend VersionSort = Major * 100000000 +         Minor * 100000 + coalesce(Patch, 0)
| summarize arg_max(VersionSort, SoftwareVersion) by DeviceId
| project DeviceId, LatestInstalledPHP = SoftwareVersion; DeviceProcessEvents
| where Timestamp > ago(30d) | where FileName =~ "php-cgi.exe"
//| where InitiatingProcessFileName =~ "w3wp.exe"
| extend PHPVersion = extract( @"(?i)\\v?(\d+.\d+(?:.\d+)?)\\php-cgi.exe", 1, FolderPath ) | extend Major = toint(split(PHPVersion, ".")[0]), Minor = toint(split(PHPVersion, ".")[1]) | where isnotnull(Major) | where Major < 8 or (Major == 8 and Minor < 2)
| join kind=inner InternetFacingDevices on DeviceId
| join kind=leftouter LatestInstalledPHP on DeviceId
| summarize     FirstExecution = min(Timestamp), LastExecution = max(Timestamp),     Executions = count(),     ProcessPaths = make_set(FolderPath, 10),     IISCommandLines = make_set(InitiatingProcessCommandLine, 10),     PHPCommandLines = make_set(ProcessCommandLine, 10)     by DeviceName, LatestInstalledPHP, IsInternetFacing,PHPProcessOlderVersion= PHPVersion
 | order by Executions desc
```
