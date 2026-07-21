**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1213.002 | Data from Information Repositories: SharePoint |

**Author:** Sergio Albea (06/08/2024)

---

**Anonymous access to files by suspicious IP addresses**

This new query review connections using an anonymous proxy and having activities with OneDrive/Sharepoint files.
I found multiple cases with malicious IP's using urn:spo:anon# or anonymous access which are examples of an external user accessing a SharePoint/OneDrive file shared without any restrictions.

```
CloudAppEvents
| where IsAnonymousProxy == 1
| where Application !has "Exchange"
| where RawEventData !has "@"
| extend userID = RawEventData.UserId
| extend SourceRelativeUrl = RawEventData.SourceRelativeUrl
| project Timestamp,ObjectName,ObjectType,SourceRelativeUrl,CountryCode,IPAddress,userID,ActionType, Application, DeviceType, OSPlatform, ISP,IsAdminOperation, AccountType, IsImpersonated, UserAgentTags, OAuthAppId, RawEventData
| sort by ObjectName
```
