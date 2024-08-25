**Enriching CVE Tables with CVE Mitre Data**

**Description**: This query takes the info from the CVE Mitre site (https://cve.mitre.org) enriching the Defender tables with different URL's related to the vulnerability itself, how to remediate it and additional information.

```
et CVE = externaldata(CVEData:string)
[@"https://cve.mitre.org/data/downloads/allitems.csv"] with (format="txt");
CVE
| where CVEData !startswith '"' and CVEData !startswith ","
| extend Name = split(CVEData, ',')[0],
 Status = split(CVEData, ',')[1],
 Description = split(CVEData, ',')[2],
 AdditionalInfo0 = split(CVEData, '"')[3]
| extend AdditionalInfo1 = split(AdditionalInfo0, '|')[0],
 AdditionalInfo2 = split(AdditionalInfo0, '|')[1],
 AdditionalInfo3 = split(AdditionalInfo0, '|')[2]
| extend Description = substring(Description, 1)
| extend Name = tostring(Name)
// You can use this line to search for specific CVE ID | where Name has ""
| join kind=inner ( DeviceTvmSoftwareVulnerabilities) on $left.Name == $right.CveId
| join kind=inner ( DeviceTvmSoftwareVulnerabilitiesKB) on $left.Name == $right.CveId
| project Name,DeviceName, CvssScore, IsExploitAvailable, SoftwareName ,Status, Description, AdditionalInfo0,AdditionalInfo1, AdditionalInfo2, AdditionalInfo3
```
