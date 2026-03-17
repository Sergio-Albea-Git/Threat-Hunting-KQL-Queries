**[IC] - Catching emojis on email Subjects**

| Technique ID | Title    |
| ---  | --- |
| T1566 | Phishing |


| Author | Sergio Albea (17/03/2026)   |
| ---  | --- |

Marketing emails use Emojis all the time… but attackers use them too because they catch attention and increase the chance someone clicks:
- ⚠️ Urgent messages
- 📦 Delivery notifications
- 📄 Fake invoices
- 🔐 Password resets

Identify and classify cases on Email Subjects can be converted in useful detections. It query identify:
- Emails received with icons in the subject
- Where the URL was clicked
- Excluding cases where the sender is added as allowed either in the organization or user level
- Summarise by number of Emails, number of distinct recipients and also identify if the messages were delivered into Inbox Folders
```
// Sergio Albea 17-03-2026 ©️
EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(Subject)
| extend Icons = extract_all(@"([\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}])", Subject)
| where isnotempty(Icons)
| join kind=inner UrlClickEvents on NetworkMessageId
| where UserLevelPolicy !has 'Allow' 
| where OrgLevelPolicy !has 'Allow'
| extend SenderIP = iff(isnotempty( SenderIPv4),SenderIPv4,SenderIPv6)
| extend geo_ip = tostring(geo_info_from_ip_address(SenderIP).country)
//| where Subject contains "⚠️" 
| summarize Distinct_Recipients=dcount(RecipientEmailAddress),make_set(RecipientEmailAddress),Emails=count() by Subject,SenderIP,geo_ip,ActionType, Workload, Url, ThreatTypes, LatestDeliveryLocation
| order by Emails, Distinct_Recipients
```
