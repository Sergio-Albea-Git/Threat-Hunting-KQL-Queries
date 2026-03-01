**[IA] - Monitoring Explorer-Initiated External Traffic**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1105  |  Ingress Tool Transfer |

| Author | Sergio Albea (01/03/2026)   |
| ---  | --- |

**Description:** I was reading this article today on cybersecuritynews (🔗 ⬇️ ) about attackers abusing Windows File Explorer + WebDAV to deliver malware, and it made me think about how to monitor this threat.
The attack makes File Explorer connect to an external location that looks like a normal folder. From the user side nothing feels strange… but in reality explorer.exe is establishing an internet connection to attacker infrastructure.
As I usually say, it’s often better to focus on IOAs (how the activity happens) rather than only URLs or domains, because those are trivial for attackers to change. The behaviour is what tends to stay consistent.
The following KQL Query filter identify external connections initiated by Explorer + option to exclude False Positives based on URLs + option to specify connections to specific countries.

```
//Sergio Albea
DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any (dynamic(['bing.com','assets.msn.com']))) 
| extend geo_ip = tostring(geo_info_from_ip_address(RemoteIP).country)
//| where geo_ip !in ('','')
| summarize Connections=count(),make_set(RemoteUrl),make_set(RemoteIP) by DeviceName,DeviceId,InitiatingProcessFileName, geo_ip, Timestamp, ReportId
```
