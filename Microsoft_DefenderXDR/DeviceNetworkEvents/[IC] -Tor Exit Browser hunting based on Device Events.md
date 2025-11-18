**[IC] -Tor Exit Browser hunting based on Device Events**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1090.003 | Multi-hop Proxy  |

| Author | Sergio Albea (30/10/2025)   |
| ---  | --- |

**Description:** A Tor exit node is the last server in the Tor network that your traffic passes through before it reaches the public internet so it is the one that actually makes the connection to website.
In this particular query, I am getting the devices with connections to Tor Exit Nodes, to list to which node are connecting and possible suspicious URLs with connections to the mentioned servers.
```
//Author Sergio Albea 18-11-2025
let TorExitNodesHistoric = externaldata(IP:string, ActiveDates:string, Source:string) ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-tor-exit-historic.json.zip'] with(format="multijson"); 
TorExitNodesHistoric 
| extend ActiveDates = split(ActiveDates, ',') 
| extend Country = tostring(geo_info_from_ip_address(IP)['country'])
| summarize ActiveDays = array_length(make_set(ActiveDates)) by Country,IP,Source
| join kind=inner (DeviceNetworkEvents) on $left.IP == $right.RemoteIP
| summarize  by Source,DeviceName,TOR_Exit_Node= LocalIP,Country,ActiveDays,RemoteUrl, InitiatingProcessAccountName, InitiatingProcessVersionInfoProductName, ActionType//, Timestamp,ReportId
| order by ActiveDays
```
