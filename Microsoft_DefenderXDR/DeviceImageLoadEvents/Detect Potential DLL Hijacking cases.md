**Detect Potential DLL Hijacking cases**

Hijacklibs.net is a project that provides an curated list of DLL Hijacking candidates.As mentioned in their website: "DLL Hijacking is, in the broadest sense, tricking a legitimate/trusted application into loading an arbitrary DLL. Defensive measures such as AV and EDR solutions may not pick up on this activity out of the box, and allow-list applications such as AppLocker may not block the execution of the untrusted code. There are numerous examples of threat actors that have been observed to leverage DLL Hijacking to achieve their objectives."
Based on that list, I decided to look for the cases where the SHA256 of the DLL’s presents on the DeviceImageLoadEvents (table that contains information about DLL loading events) , is listed as a candidate into the mentioned site and the KQL Query show the URL’s with the corresponding research to understand the Threat.
```
let dll_hijacking_source = externaldata
(Name:string,Author:string,Created:string,Vendor:string,CVE:string,ExpectedLocations:string,VulnerableExecutablePath:string,VulnerableExecutableType:string,VulnerableExecutableAutoElevated:string,VulnerableExecutablePrivilegeEscalation:string,VulnerableExecutableCondition:string,VulnerableExecutableSHA256:string,VulnerableExecutableEnvironmentVariable:string,Resources:string,Acknowledgements:string,URL:string)
[@"https://hijacklibs.net/api/hijacklibs.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceImageLoadEvents
| join kind=inner ( dll_hijacking_source) on $left.SHA256 == $right.VulnerableExecutableSHA256
| where isnotempty( VulnerableExecutableSHA256)
| summarize by DeviceId, DeviceName, ActionType, FileName, FolderPath, SHA256,VulnerableExecutableSHA256,Resources, Acknowledgements,URL, FileSize, InitiatingProcessAccountName,InitiatingProcessAccountDomain, InitiatingProcessAccountUpn, InitiatingProcessIntegrityLevel, InitiatingProcessFileName, InitiatingProcessVersionInfoCompanyName, Name, Author, VulnerableExecutableType, VulnerableExecutableEnvironmentVariable
```
