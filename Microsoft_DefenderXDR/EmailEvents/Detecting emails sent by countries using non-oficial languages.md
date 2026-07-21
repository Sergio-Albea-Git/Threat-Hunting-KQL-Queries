**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1566 | Phishing |

**Author:** Sergio Albea (20/07/2026)

---

**Detecting emails sent by countries using non-oficial languages**

**Description**: During my vacation, I've been enjoying conversations with people from different countries about their national teams and the World Cup. What I don't expect (although it certainly can happen) is a Mexican speaking Japanese, a Spaniard speaking Russian, or an Egyptian speaking Spanish. Yet, this is becoming more and more common, and I love it. Our world is becoming increasingly connected and multicultural. However, the same logic doesn't always apply to emails. That thought inspired me to build a KQL query that I'll explore further after my break, but I wanted to share it now. The idea is detect emails where the language doesn't match the expected language(s) of the sender's country. While this isn't a detection by itself, it can be a valuable hunting signal when combined with other indicators. KQL Query Filter options:
- EmailCount < X → Filter based on the number of emails observed.
- Country !in ("Spain") → Exclude countries with a higher false-positive ratio.
- SenderDomains !in ("Domain1","Domain2") → Exclude trusted sender domains.

```
let CountryLanguageMap = externaldata(ISO2:string,Country:string,ExpectedLanguages:string)
    [@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/refs/heads/main/Security-Lists/country_Language.csv"] with (format = "csv",ignoreFirstRecord = true)
    | extend ExpectedLanguagesArray =   split(tolower(ExpectedLanguages), ";");
EmailEvents
| extend SenderIP = iff(isnotempty(SenderIPv4),SenderIPv4,SenderIPv6)
| where isnotempty(SenderIP) and isnotempty(EmailLanguage)
| extend GeoInfo = geo_info_from_ip_address(SenderIP)
| extend Country = tostring(GeoInfo.country)
| extend DetectedLanguage = tolower(substring(tostring(EmailLanguage), 0, 2)) | lookup kind=leftouter CountryLanguageMap on Country
| where isnotempty(ExpectedLanguages) and isnotempty(DetectedLanguage) and DetectedLanguage !in ("un", "xx") and array_index_of( ExpectedLanguagesArray, DetectedLanguage) == -1
| summarize 
    EmailCount = count(),FirstSeen = min(Timestamp),LastSeen = max(Timestamp),Subjects = make_set(Subject, 10),ThreatTypes = make_set(ThreatTypes, 10),SenderDomains = make_set(SenderFromDomain, 10)
    by SenderIP,Country,DetectedLanguage,EmailLanguage
| where EmailCount < 10 and Country !in ("United States") and SenderDomains !in ("Domain1","Domain2")
```
