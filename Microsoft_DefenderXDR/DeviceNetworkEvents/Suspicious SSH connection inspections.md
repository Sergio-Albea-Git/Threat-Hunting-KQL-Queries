**Suspicious SSH connection inspections**

**Description:** The aim of this query is detect SSH connections attempts where the external sources are specifying babeld (Network Protocol) or Conker (Network Conf. Manager) as parameters to establish a connection, is detect suspicious activity such as:

- Unauthorized SSH connections.
- Malicious use of SSH for lateral movement within a network.
- Exfiltration attempts via SSH tunneling.
```
DeviceNetworkEvents
| where ActionType has "SshConnectionInspected"
| extend CountryIP = tostring(geo_info_from_ip_address(RemoteIP).country), server = tostring(parse_json(AdditionalFields).server)
| where isnotempty(CountryIP)
| where server contains "babeld" or server contains "conker"
| project Timestamp,ActionType, RemoteIP, RemotePort,CountryIP, server, auth_success = tostring(parse_json(AdditionalFields).auth_success), client = tostring(parse_json(AdditionalFields).client)```
