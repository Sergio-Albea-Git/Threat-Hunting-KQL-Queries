**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1082 | System Information Discovery |

**Author:** Sergio Albea (17/11/2026)

---

**[IC] - Optimizely Compromised: Identify Devices that visited the Malicious URLs-Domains**

During the Optimizely compromise investigation, the article below list different domains related to the reported compromise.
This KQL determine which devices generated the most connections and whether they contacted multiple malicious domains + which type of malicious URLs are ( PayLoad, Data Exfiltration, Screenshoot, others).

Investigation Source: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/

```
DeviceNetworkEvents 
| where Timestamp > ago(3d) 
| where RemoteUrl contains "1688360.cc" or RemoteUrl contains "5vobauua3ojpklx.icu" or RemoteUrl contains "eil786npto9u5bq.icu" or RemoteUrl contains "webshell.lol" 
| extend ActivityType=case(RemoteUrl contains "1688360.cc" and RemoteUrl contains "hit.php","Potential Cookie & Screenshot Exfiltration",RemoteUrl contains "1688360.cc" and RemoteUrl contains "card.php","Potential Card Data Exfiltration",RemoteUrl contains "1688360.cc" and RemoteUrl contains "track.js","Malicious JavaScript Payload",RemoteUrl contains "1688360.cc","Malicious Payload / Exfiltration Infrastructure",RemoteUrl contains "5vobauua3ojpklx.icu","iOS Exploit Router 1",RemoteUrl contains "eil786npto9u5bq.icu","iOS Exploit Router 2",RemoteUrl contains "webshell.lol","JavaScript Injection Infrastructure","Unknown") 
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Domains=make_set(RemoteUrl,20), ActivityType=make_set(ActivityType,10) by DeviceName, DeviceId
```
