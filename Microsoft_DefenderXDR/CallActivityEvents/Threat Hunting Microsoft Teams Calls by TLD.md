**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1566.003 | Spearphishing via Service |

**Author:** Sergio Albea (30/09/2026)

---

**Threat Hunting Microsoft Teams Calls by TLD**

**Description**: Another small hunting idea using CallActivityEvents Table.
The query extracts the Top-Level Domain (TLD) from the person performing the action in a Microsoft Teams call and enriches it with an external country list.
In this example, I exclude .CH to quickly surface activity where the originator is using a domain associated with another country.
A different hunting angle to spot unexpected external participants, unusual call activity, or simply identify interactions that deserve a closer look.
Of course, a foreign TLD is not malicious by itself — it is just another piece of context for the hunter. 🔎

```
let CountryList = externaldata(Country:string, Code:string)[
    "https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/d37d54bc90f833d5016c7105f6d7a42802b8d6fa/Security-Lists/country_list.csv"]
with(format="csv", ignoreFirstRecord=true);
CallActivityEvents
| where isnotempty(OriginatorUpn)
| extend Domain = tostring(split(OriginatorUpn, "@")[1])
| extend TLDdomain = toupper(tostring(split(Domain, ".")[-1]))
| where TLDdomain !in ('CH')
| join kind=inner CountryList on $left.TLDdomain == $right.Code
| summarize by  TimeGenerated,ActivityType, OriginatorUpn, Domain, Code, Country
```
