**Identifying Devices by Vendor&Country based on Inbound Connections**

This KQL Query focuses on summarizing the number of devices attempting to connect to exposed servers, categorized by vendor and it country, by decoding their MAC addresses. 
This information can help you to identify if an unusual combination appears (e.g., a Chinese-manufactured device but the connection originates from Russia), detect nation-state attack patterns, as certain adversaries often use infrastructure in specific regions and
cases where attackers often route traffic through VPNs, proxies, or compromised hosts to obfuscate their real location.

```
// Importing the Vendor MAC Address table 
let mac_info = externaldata(MAC: string,Vendor:string ,Country:string)[@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/refs/heads/main/Security-Lists/mac_list.csv"] with (format="csv", ignoreFirstRecord=True);
// selecting the Source MAC Address of the remote connections
DeviceNetworkEvents 
| extend AdditionalFields = parse_json( AdditionalFields)
| extend direction =  AdditionalFields["direction"]
| where direction has "In"
| extend Source_Mac =  tostring(AdditionalFields["Source Mac"])
// formatting the First 3 Octets of the MAC Address
| extend MAC_Prefix_format = replace(":", "-", Source_Mac)
| extend MAC_Prefix = substring(MAC_Prefix_format, 0, 8)
// joining the Vendor MAC address info table
| join kind=inner (mac_info) on $left.MAC_Prefix == $right.MAC
// Getting the Country of the RemoteIPs
| extend geo_ip = tostring(geo_info_from_ip_address(RemoteIP).country)
| where isnotempty (geo_ip)
| distinct Source_Mac,Vendor, Device_Component_Country= Country, RemoteIP_Country = geo_ip , RemoteIP , ActionType, DeviceName
```
