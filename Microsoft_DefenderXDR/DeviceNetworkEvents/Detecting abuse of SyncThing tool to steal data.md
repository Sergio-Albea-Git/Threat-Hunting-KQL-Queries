**Detecting abuse of SyncThing tool to steal data**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1071.002 | Application Layer Protocol: File Transfer Protocols  |

| Author | Sergio Albea (06/11/2025)   |
| ---  | --- |

**Description:** Syncthing is a peer-to-peer file synchronization utility, designed to sync files between devices on a local network or between remote devices over the Internet.
This utility to exfiltrate data, has been already abused to exfiltrate data by Malicious actor.
The following KQL Query detect connections to external IPs via the mentioned software and the corresponding country.

```
DeviceNetworkEvents
| extend geo_info = tostring(geo_info_from_ip_address(RemoteIP).country)
| where InitiatingProcessCommandLine has "syncthing.exe --no-browser"
| summarize by DeviceName,LocalIP, RemoteIP,geo_info, InitiatingProcessVersionInfoProductName, InitiatingProcessCommandLine, ActionType
```
