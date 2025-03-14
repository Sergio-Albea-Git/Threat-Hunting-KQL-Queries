**Detect unusual/suspicious RTT values based on DNS Answers**

**Description:** Round Trip Time (RTT) analysis is a powerful value for threat hunting, revealing:

- C2 servers hosted in unusual locations (High RTT). (| where rtt > 100)
- Malware hiding inside local networks (Low RTT). (| where rtt < 5 )
- DNS tunneling activity based on RTT anomalies.
- Tor/VPN evasion techniques (RTT fluctuation detection).
- Compromised infrastructure using offshore hosting (Known malicious IPs with high RTT).

```
DeviceNetworkEvents
| extend TTLs = todynamic(tostring(parse_json(AdditionalFields).TTLs))
| mv-expand TTLs
| extend answers = todynamic(tostring(parse_json(AdditionalFields).answers))
| extend answersext = todynamic(tostring(parse_json(AdditionalFields).answers))
| extend rtt = todynamic(tostring(parse_json(AdditionalFields).rtt))
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
| where rtt > 100
| project   DeviceName, RemoteIP,answers,Geo_info_RemoteIP, Geo_info_answer,rtt, TTLs
```
