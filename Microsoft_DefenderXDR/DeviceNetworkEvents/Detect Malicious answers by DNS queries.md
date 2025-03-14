**Detect Malicious IP answers by DNS queries**

**Description:** The aim of this query is detect suspicious IP answers from DNS Queries, validating them with an external TI Feed and be alerted when there are some matches.

```
let IPList = externaldata (IP:string) ["https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"] with(format="txt")
| where IP !startswith "#"
| extend IP_ = split(IP, "	")
| extend IP = tostring(IP_[0])
| extend BL = toint(IP_[1]);
 DeviceNetworkEvents
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
| join kind=inner (IPList) on $left.answers == $right.IP
| extend Geo_info_answer = tostring(geo_info_from_ip_address(answers).country)
| extend Geo_info_RemoteIP = tostring(geo_info_from_ip_address(RemoteIP).country)
| where BL > 1
| summarize dcount(answers),make_set(answers),make_set(query),make_set(Geo_info_answer),make_set(ActionType) by DeviceName, RemoteIP, Geo_info_RemoteIP
| order by dcount_answers
```
