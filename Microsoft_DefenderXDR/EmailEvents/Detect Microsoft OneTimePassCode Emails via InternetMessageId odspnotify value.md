**Detect Microsoft OneTimePassCode Emails via InternetMessageId odspnotify value**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1621  |  MFA abuse|

| Author | Sergio Albea (19/04/2026)   |
| ---  | --- |

**Description:** If you are in a country where there is more than one local language, like me in Switzerland, it is challenging to create detections based on subjects because you can have them in multiple languages. Therefore, focusing on the value odspnotify inside of InternetMessageId - which does not change based on the language - helps to detect cases.
This one is related to OneTimePassCode and is useful to identify if the code is sent to other domains, which could mean that a forwarding rule has been configured or some other suspicious activity.

```
//Sergio Albea  19-04-2026 ©️
EmailEvents
| where InternetMessageId contains "OneTimePasscode"
| where RecipientDomain !in ('trustedomain.ch','trustedomain2.ch')
| project InternetMessageId,Subject, RecipientDomain, RecipientEmailAddress, ReportId
```
