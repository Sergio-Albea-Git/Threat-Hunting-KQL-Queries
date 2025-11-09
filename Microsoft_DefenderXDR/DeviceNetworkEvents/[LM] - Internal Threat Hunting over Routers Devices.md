**[LM] - Internal Threat Hunting over Routers Devices**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1018 | Remote System Discovery  |

| Author | Sergio Albea (30/10/2025)   |
| ---  | --- |

**Description:** The query below correlates device inventory, IP assignment and network events to identify internal endpoints attempting to connect to routers — including whether they succeeded and via Web or Application access. Attack traffic often aligns with failed HTTP/HTTPS attempts or unknown device names.

```
//Author Sergio Albea 30-10-2025
DeviceInfo
| where DeviceSubtype has "Router" 
| join kind=inner (DeviceNetworkInfo | where isnotempty(IPAddresses)) on $left.DeviceName == $right.DeviceName
| extend d = todynamic(IPAddresses)                          // works for string or dynamic
| extend IP = tostring(iif(array_length(d) > 0, d[0].IPAddress, ""))
| join kind=inner (DeviceNetworkEvents | where isnotempty(RemoteIP) and isnotempty(RemoteUrl)) on $left.IP == $right.RemoteIP
| where RemoteUrl contains "IP"  and isnotempty(Vendor)
// If there are devices identified as valid to connect/manage your routers, you can exclude them using the next condition
// where DeviceName2 !in ("Device1","Device2")
| extend Access_Type = case(RemoteUrl startswith "http", "🌎 Web","⚙️ Application")
| extend Connection_Result = case(ActionType has "ConnectionSuccess", "✅ ConnectionSuccess","❌ ConnectionFailed")
| summarize make_set(OSPlatform),make_set(InitiatingProcessFileName), Total_connections=count() by  Vendor,Connection_From=DeviceName2,LocalIP,Access_Type,Connection_To=RemoteUrl, RemoteIP,DeviceSubtype=strcat("🛜 ",DeviceSubtype), Connection_Result```
