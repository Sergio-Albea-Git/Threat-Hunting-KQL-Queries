**Identifying methods used to establish secure communication over insecure channels**

**Description**: In this case, I have been researching about the 'curve' value into AdditionalFields field of DeviceNetworkEvents table which I identified into iana.org as two groups 'Elliptic curve' and 'Diffie-Hellman groups'.

These 2 kinds of encryption groups work to secure communication over an insecure channel, are classified by  Internet Assigned Numbers Authority (IANA), as if are 'recommended' and the Datagram Transport Layer Security status.
In addition, to take into account, the mentioned site mention:
"If an item is not marked as 'Recommended', it does not necessarily mean that it is flawed; rather, it indicates that the item either has not been through the IETF consensus process, has limited applicability, or is intended only for specific use cases"

Therefore, this KQL Query is oriented to identify if the current encryption to secure your communications is enough or if due to the level of sensitive of your information, would need to be reviewed.

```
let Courve_Source = externaldata(Value:int,Description:string,DTLSOK:string,Recommended:string,Reference:string)
[@"https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv"] with (format="csv");
DeviceNetworkEvents
| extend curve = parse_json(AdditionalFields).curve
| extend curve = tostring(curve)
| extend server_name = parse_json(AdditionalFields).server_name
| extend server_name = tostring(server_name)
| extend RemoteIPCountry = geo_info_from_ip_address(RemoteIP).country
| extend RemoteIPCountry = tostring(RemoteIPCountry)
| join kind=inner (Courve_Source) on $left.curve == $right.Description
// listing non-recommended curve versions or communications where the Datagram Transport Layer Security (DTLS) is not OK
| where DTLSOK has "N" or Recommended has "N"
// adding DeviceInfo table to show Device OS info
| lookup kind=inner ( DeviceInfo) on $left.DeviceName == $right.DeviceName
| summarize Totalconnections=count() by RemoteIP , RemoteIPCountry, OSDistribution, OSPlatform,OSVersion, ClientVersion, OSBuild, OSArchitecture,DeviceName, LocalIP,ActionType, RemotePort, Protocol, server_name,curve,DTLSOK, Recommended
| order by Totalconnections
```
