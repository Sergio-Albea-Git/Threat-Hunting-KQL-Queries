**ASN generating high number of connection requests based on average**

**Description:** Identify An ASN that typically handles an average of X connection requests per day over a consistent 7-day period suddenly triples—or more—the number of requests. (You can adjust this line to define the exact multiplication threshold). In addition, identify if during the last week, a new ASN has triggered more than 1K connection attempt during a day.
```
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string) ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip'] with (ignoreFirstRecord=true));
let daily =
    DeviceNetworkEvents
    | where isnotempty(RemoteIP) and RemoteIPType !has "Private"
    | where Timestamp >= ago(7d)
    | evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true)
    | where isnotempty (CIDRASN)
    | extend Day = format_datetime(startofday(Timestamp), 'yyyy-MM-dd')
    | summarize    Success_Connections = countif(ActionType == "ConnectionSuccess"),
                   Attempts_Connections = countif(ActionType == "ConnectionAttempt" or ActionType =="ConnectionFailed"),
                   Inspected_Connections = countif( ActionType endswith "inspected"),
                   Requested_Connections = countif(ActionType == "ConnectionRequest"),
                   make_set(CIDR),make_set(RemoteIP),Connections_x_day = count() by CIDRASN,CIDRASNName, Day;
let summary =
    daily  | summarize TotalConnections = sum(Connections_x_day),Distinct__Days = count(),AvgConnectionsPerDay = avg(Connections_x_day)by CIDRASN;
daily
| join kind=inner (summary) on CIDRASN
| extend Multiply_avg = AvgConnectionsPerDay * 4
| where Multiply_avg < Connections_x_day or (Distinct__Days == 1 and Attempts_Connections > 1000)
| project  CIDRASNName,CIDRASN,set_CIDR,set_RemoteIP, Day,Distinct__Days ,Connections_x_day, AvgConnectionsPerDay, TotalConnections, Success_Connections, Attempts_Connections, Inspected_Connections,Requested_Connections
| order by Attempts_Connections
```
