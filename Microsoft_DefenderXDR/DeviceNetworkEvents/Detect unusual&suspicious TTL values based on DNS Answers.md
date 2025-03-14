**Detect unusual/suspicious TTL values based on DNS Answers**

**Description:** Time to live (TTL) values in DNS responses provide valuable threat-hunting insights, including:

- Fast-flux botnets (rotating IPs with low TTLs). 
- Malware C2 detection (extremely low TTLs). ( | where TTLs < 10 )
- DNS tunneling (high TTLs or changing TTLs). ( | where TTLs > 86400 )
- Fake domains mimicking real services (TTL anomalies).
- Evasive infrastructure constantly changing TTL values.

```
 DeviceNetworkEvents
| extend TTLs = todynamic(tostring(parse_json(AdditionalFields).TTLs))
| mv-expand TTLs
| extend answers = todynamic(tostring(parse_json(AdditionalFields).answers))
| extend answersext = todynamic(tostring(parse_json(AdditionalFields).answers))
| extend query = (tostring(parse_json(AdditionalFields).query))
| mv-expand answers
| extend Type =
    case(
        answers matches regex @"^(\d{1,3}\.){3}\d{1,3}$", "IPv4",  
        answers matches regex @"^([a-fA-F0-9:]+)$", "IPv6",        
        answers contains ".", "URL",                               
        "Unknown"                                                 
    )
| where Type has "IPv4"
| extend tostring(answers)
| extend Geo_info_answer = tostring(geo_info_from_ip_address(answers).country)
| extend Geo_info_RemoteIP = tostring(geo_info_from_ip_address(RemoteIP).country)
| where TTLs > 86400
| project   DeviceName, RemoteIP,answers,Geo_info_RemoteIP, Geo_info_answer, TTLs
```
