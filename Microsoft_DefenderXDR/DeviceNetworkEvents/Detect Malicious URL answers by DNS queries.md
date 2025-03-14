**Detect Malicious URL answers by DNS queries**

**Description:** The aim of this query is detect suspicious URL answers from DNS Queries, validating them with an external TI Feed and be alerted when there are some matches.

```let URLHausOnlineRAW = externaldata (UHFeed:string) ["https://urlhaus.abuse.ch/downloads/csv_online/"] with(format="txt")
| where UHFeed !startswith "#"
| extend UHRAW=replace_string(UHFeed, '"', '')
| project splitted=split(UHRAW, ',')
| mv-expand id=splitted[0], dateadded=splitted[1], UHUrl=splitted[2], UHurl_status=splitted[3], UHlast_onlin=splitted[4], UHthreat=splitted[5], UHtags=splitted[6], UHLink=splitted[7], UHReporter=splitted[8]
| extend UHUrl = tostring(UHUrl)
| extend UHUrlDomain = tostring(parse_url(UHUrl).Host)
| project-away splitted;
DeviceNetworkEvents
| extend answers = todynamic(tostring(parse_json(AdditionalFields).answers))
| extend answersext = todynamic(tostring(parse_json(AdditionalFields).answers))
| mv-expand answers
//| extend geo_Remote_answers = todynamic(tostring(geo_info_from_ip_address(answers).country))
| extend Type =
    case(
        answers matches regex @"^(\d{1,3}\.){3}\d{1,3}$", "IPv4",   // Matches IPv4 format
        answers matches regex @"^([a-fA-F0-9:]+)$", "IPv6",         // Matches IPv6 format
        answers contains ".", "URL",                                // Checks if it contains a dot (common in URLs)
        "Unknown"                                                      // Default case
    )
| where Type has "URL"
| extend tostring(answers)
| join kind=inner (URLHausOnlineRAW) on $left.answers == $right.UHUrl
| extend geo_Remote_ip = tostring(geo_info_from_ip_address(RemoteIP).country)
| project Timestamp,DeviceName,LocalIP,RemoteIP,geo_Remote_ip,MaliciousAnswers = UHUrl,answersext,UHUrlDomain, ActionType
```
