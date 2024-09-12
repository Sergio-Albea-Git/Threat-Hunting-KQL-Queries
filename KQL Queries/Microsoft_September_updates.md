**Devices affected by September Security updates which includes 4 Zero-days & 79 Vulnerabilities fixed**

**Description:** Microsoft’s September 2024 Patch has addressed a significant number of security vulnerabilities, including four zero-day exploits and a total of 79 vulnerabilities across various products.
This query helps to identify devices affected by the mentioned updates and add a column related to the corresponding updates/remediations information provided by Microsoft.

```
DeviceTvmSoftwareVulnerabilities | join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB) on $left.CveId == $right.CveId | where RecommendedSecurityUpdate contains "September 2024 Security Updates" | 
extend URLSecurityUpdate = strcat("https://msrc.microsoft.com/update-guide/en-US/advisory/", CveId) | project CveId,IsExploitAvailable,URLSecurityUpdate,CvssScore,VulnerabilitySeverityLevel,RecommendedSecurityUpdate, DeviceName, DeviceId,RecommendedSecurityUpdateId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion | order by CvssScore
```
