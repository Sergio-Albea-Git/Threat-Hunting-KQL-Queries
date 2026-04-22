**Detect Potential Malicious Emails Based on InternetMessageId Dates**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1566.002  |  Phishing: Spearphishing Link|

| Author | Sergio Albea (19/04/2026)   |
| ---  | --- |

**Description:** The are some cases where InternetMessageIds contain a date integrated, sometimes encoded, sometimes not. Therefore, we have two timestamps to compare:

- InternetMessageId date → usually when the sending system generated the message.
- Timestamp (EmailEvents) → when Microsoft received/processed the email.

So if we compare “when it was created” vs “when it arrived”, we can detect cases such as emails created by the system but, due to local configuration, email campaigns that deliver slowly, or messages that were postponed compared to when they were received by Microsoft.
The ratio of true positive was really high and multiple emails were not detected as a Threat so good case to add as a detection

```
//Sergio Albea  19-04-2026 ©️
EmailEvents
| extend Timestamp_YYYYMMDD = format_datetime(Timestamp, "yyyyMMdd")
| extend Timestamp_IM = format_datetime(Timestamp, "yyyyMM")
| extend IMF = tostring(InternetMessageId)
| where IMF contains Timestamp_IM
| extend StartPos = indexof(IMF, Timestamp_IM)
| extend Extracted_IMF_Date = iff(StartPos >= 0 and strlen(IMF) >= StartPos + 8, substring(IMF, StartPos, 8), "")
| extend Extracted_IMF_Date_dt = todatetime(strcat(substring(Extracted_IMF_Date,0,4), "-", substring(Extracted_IMF_Date,4,2), "-", substring(Extracted_IMF_Date,6,2)))
| where Timestamp > Extracted_IMF_Date_dt
| extend case1 = iff(IMF contains Timestamp_YYYYMMDD, "valid", "other")
| join kind=inner EmailUrlInfo on NetworkMessageId
// comment the line below if you want to see all InternetMessageId with date populated and the cases detected as Threat
| where case1 has 'other' and isempty(ThreatTypes)
| summarize make_set(Url), make_set(SenderFromDomain) by case1, Timestamp_YYYYMMDD, Timestamp_IM, Extracted_IMF_Date, IMF, InternetMessageId, ThreatTypes, Subject,SenderIP=iff(isnotempty(SenderIPv4),SenderIPv4,SenderIPv6), ReportId
```
