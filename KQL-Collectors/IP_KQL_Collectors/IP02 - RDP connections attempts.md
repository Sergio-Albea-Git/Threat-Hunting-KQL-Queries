**IP02 - RDP connections attempts**

**Description:**  Collecting IPs with RDP Connections attempts from top5 risk countries.
```
{
  "Query": " DeviceNetworkEvents |  where Timestamp > ago(1d) | where LocalPort == '3389' | extend geo_ip = tostring(geo_info_from_ip_address(RemoteIP).country) | where isnotempty(geo_ip) and geo_ip in ('Russia','China','Nigeria','Iran','North Korea')|  extend Time_ = format_datetime( Timestamp, 'dd-MM-yyyy') | project geo_ip, RemoteIP, RemotePort,ActionType, InitiatingProcessCommandLine,Time_ | extend rawHash = substring(tostring(hash_sha256(strcat(1, tostring(rand())))), 0, 32) | extend GeneratedUUID = strcat( substring(rawHash, 0, 8), '-', substring(rawHash, 8, 4), '-', substring(rawHash, 12, 4), '-', substring(rawHash, 16, 4), '-', substring(rawHash, 20, 12)) "
}
```
