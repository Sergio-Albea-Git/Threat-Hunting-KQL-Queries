**Identifying Devices by Vendor based on Inbound Connections**

This KQL Query focuses on summarizing the number of devices attempting to connect to exposed servers, categorized by vendor, by decoding their MAC addresses. This information can help you
to identify unexpected devices vendors, detect virtual devices or correlate specific manufacturers with known threats:

```
// Importing the Vendor MAC Address table 
let mac_info = externaldata(mac: string)[@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/refs/heads/main/Security-Lists/mac_list_Type2.txt"] with (format="txt", ignoreFirstRecord=True);
let info =mac_info
| extend SplitValues = split(mac, ",")
| extend mac = tostring(SplitValues[0]), vendor_sn = tostring( SplitValues[1]), vendor = tostring(SplitValues[2])
| project mac,vendor;
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
| join kind=inner (info) on $left.MAC_Prefix == $right.mac
// Getting the Country of the RemoteIPs
| extend geo_ip = tostring(geo_info_from_ip_address(RemoteIP).country)
| where isnotempty (geo_ip)
| summarize Different_Countries_using_Manufacter_Device= dcount(geo_ip), make_set(geo_ip),Total_devices_by_vendor=dcount(Source_Mac),Total_different_RemoteIPs=dcount(RemoteIP),make_set(RemoteIP)  by vendor```
