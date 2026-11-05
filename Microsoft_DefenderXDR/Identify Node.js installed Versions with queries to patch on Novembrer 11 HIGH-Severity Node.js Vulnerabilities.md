**Author:** Sergio Albea (05/11/2026)

**Identify/Upgrade Node.js installed Versions with queries to patch on Novembrer 11 HIGH-Severity Node.js Vulnerabilities**

Node.js has announced upcoming security updates addressing multiple vulnerabilities, including high-severity issues. Organizations should start identifying installed Node.js versions across their environments, especially outdated or End-of-Life (EOL) releases that may no longer receive security patches.
I created the following Query to quickly identify devices running Node.js, review their installed versions, and prioritize those requiring attention before the security updates become available.

Node.js post : https://nodejs.org/en/blog/vulnerability/november-2026-security-releases

```
DeviceTvmSoftwareInventory | where SoftwareName contains "node.js" or SoftwareName contains "nodejs" 
| extend MajorVersion = toint( extract(@"^v?(\d+)", 1, SoftwareVersion)) 
| extend SupportStatus = 
case( MajorVersion == 26, "Active LTS", MajorVersion in (22, 24), "Maintenance LTS",     MajorVersion == 27, "Alpha",     MajorVersion in (25, 23, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 0), "End of Life", "Unknown") 
| extend PatchReadiness = 
case( SupportStatus == "End of Life", "Migration required - No official security patches",     MajorVersion in (22, 24, 26), "Supported - Apply November 11 security update",     MajorVersion == 27, "Alpha - Review unsupported production deployment", "Review manually") 
| extend Priority = case( SupportStatus == "End of Life", 1, MajorVersion == 27, 2,     MajorVersion in (22, 24, 26), 3, 4) 
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, MajorVersion, SupportStatus, PatchReadiness, Priority
```
