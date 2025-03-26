**Identify HotSpot connections shared via IPhone**

Detecting networks shared by phones with key words in their Names such as "FREE", "AIRPORT" "OPEN", can be potential cases of Evil Twin Attack where malicious actors can intercept network traffic, steal login credentials, capture sensitive data, or launch further attacks like Man-in-the-Middle (MitM) attacks.
This KQL Query helps to identify when a connection is shared by an IPhone device and for that we can use a default Gateway assigned when a connection is shared from these Apple phones which is "172.20.10.1". 




```
DeviceNetworkInfo
| where DefaultGateways has "172.20.10.1"
| extend Network_Name = tostring(parse_json(ConnectedNetworks)[0]["Name"])
| where isnotempty(Network_Name)
| extend IP_info = (todynamic(parse_json(IPAddresses)))
| mv-expand IP_info
| extend Ip_Received = tostring(parse_json(IP_info).IPAddress)
| extend IP_Type = tostring(parse_json(IP_info).AddressType)
| extend geo_ip = tostring(geo_info_from_ip_address(Ip_Received).country)
| where (Network_Name contains "Free" or Network_Name  contains "Open"  or Network_Name  contains "Airport" or Network_Name  contains "hotel")
| summarize by  Network_Name, DefaultGateways,Ip_Received, IP_Type, geo_ip, DnsAddresses,DeviceName, NetworkAdapterName, NetworkAdapterStatus, NetworkAdapterType, NetworkAdapterVendor
```
