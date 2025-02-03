**Extracting bits of TCP Flags**

This KQL Query is oriented to extract the different bits of TCP Flags which helps to review the different state of the connections and identify possible threats associated.
```
let binnary_codes = externaldata(Integer: string, binary: string)[@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/refs/heads/main/Security-Lists/binary_list.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceNetworkEvents
| extend tags = parse_json( AdditionalFields)
| extend direction =  tags["direction"]
| where direction has "In"
| extend Geo_IP = tostring(geo_info_from_ip_address(RemoteIP).country)
| where isnotempty(Geo_IP)
| extend TCPFlags =  tostring(tags["Tcp Flags"])
| join kind=leftouter  ( binnary_codes) on $left.TCPFlags == $right.Integer
| extend  num0 = strcat(substring(binary,  0,1)),num1 = strcat(substring(binary,  1,1)),num2 = strcat(substring(binary,  2,1)),num3 = strcat(substring(binary,  3,1)),num4 = strcat(substring(binary,  4,1)),num5 = strcat(substring(binary,  5,1)),num6 = strcat(substring(binary,  6,1)),num7 = strcat(substring(binary,  7,1))
| summarize make_set(binary),FIN= countif(num7 == 1),SYN= countif(num6 == 1),RST = countif(num5 == 1),PSH = countif(num4 == 1),ACK = countif(num3 == 1),URG = countif(num2 == 1),ECE = countif(num1 == 1),CWR = countif(num0 == 1),  count() by RemoteIP, Geo_IP
```
