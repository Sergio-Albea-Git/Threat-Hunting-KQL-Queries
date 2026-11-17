**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1082 | System Information Discovery |

**Author:** Sergio Albea (17/11/2026)

---

**[IC] - Optimizely Compromised: Identify Compromised Websites Visited Before the Malicious URLs**

During the Optimizely compromise investigation, the article below highlights several affected organizations, including BBC, CNN, Zoom, GitLab, IKEA, and Ledger.
We can correlate visits to these legitimate websites with subsequent connections to malicious domains to identify potential infection paths.

Investigation Source: https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/

```
DeviceInfo
let Sites = dynamic(["bbc.com","bbc.co.uk","cnn.com","zoom.com","zoom.us","gitlab.com","ledger.com","ikea.com","smartsheet.com","salesforce.com","zattoo.com"]); 
let Hits = materialize(DeviceNetworkEvents 
| where Timestamp between (datetime(2026-11-16) .. datetime(2026-11-18))
| where RemoteUrl has_any ("1688360.cc","5vobauua3ojpklx.icu","eil786npto9u5bq.icu")
| project DeviceId, HitTime=Timestamp, MaliciousURL=RemoteUrl); 
DeviceNetworkEvents 
| where Timestamp between (datetime(2026-11-16) .. datetime(2026-11-18)) 
| where RemoteUrl has_any (Sites) | join kind=inner Hits on DeviceId | where Timestamp between ((HitTime - 2m) .. HitTime) 
| project Timestamp, DeviceName, LegitimateSite=RemoteUrl, MaliciousURL, HitTime, InitiatingProcessFileName | order by HitTime asc
```
