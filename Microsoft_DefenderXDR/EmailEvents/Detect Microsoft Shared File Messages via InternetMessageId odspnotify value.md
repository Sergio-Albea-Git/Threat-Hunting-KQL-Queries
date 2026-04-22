**Detect Microsoft Shared File Messages via InternetMessageId odspnotify value**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1566.002  |  Phishing: Spearphishing Link|

| Author | Sergio Albea (19/04/2026)   |
| ---  | --- |

**Description:** I don't know how many time I suffered malicious actors sharing links via Microsoft services such as SharePoint or other sites manipulating them for phishing, malware, or other malicious purposes.
I have seen multiple detections to detect phishing campaigns based on subjects, such as detecting when an email subject ends with “with you” or contains “shared.” However, if the original mailbox is configured in another language, these rules become useless.
This change specifying the InternetMessageID value odspnotify and, in addition, specifying the first part of the InternetMessageId, which tells us the action requested or performed by the email—in this case, share.
For this detection, I recommend adding your trusted domains, but it is incredibly useful to detect when links from Microsoft systems are shared with your users from unexpected domains.

```
//Sergio Albea  19-04-2026 ©️
EmailEvents
| where InternetMessageId contains "odspnotify"
| where SenderFromDomain !in ("sharepointonline.com","trustedomain2.ch")
| extend IMF = trim(@"[<>]", tostring(InternetMessageId))
| extend IMF_Left = tostring(split(IMF, "@")[0])
| extend IMF_Parts = split(IMF_Left, ";")
| extend MessageTypeFull = tostring(IMF_Parts[0])
| extend MessageTypeName = extract(@"^(.*)-[0-9a-fA-F-]{36}$", 1, MessageTypeFull)
| extend MessageTypeGuid = extract(@"([0-9a-fA-F-]{36})$", 1, MessageTypeFull)
| where MessageTypeName has 'Share'
| extend MessageTypeAfterDash = tostring(split(MessageTypeFull, "-")[1])| join kind=inner EmailUrlInfo on NetworkMessageId
| summarize Urls=make_set(Url) by InternetMessageId,Subject, SenderDisplayName, SenderMailFromAddress, SenderFromDomain, SenderIP=iff(isnotempty(SenderIPv4),SenderIPv4,SenderIPv6), ThreatTypes,MessageTypeName,RecipientDomain, RecipientEmailAddress, ReportId
```
