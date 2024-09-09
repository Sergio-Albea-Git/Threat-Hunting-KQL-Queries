**Potential Threats or network anomalies related to ICMP Inbound Connections**

**Description**: Digging through the network logs and checking out data related to the ICMP protocol, which is often used by devices like routers to send error messages and operational info. It also handles stuff like Ping, Traceroute, and more.
With that in mind, I researched potential threats and cooked up a KQL query. This one spots inbound connection attempts that could be tied to ICMP Tunneling, DDoS, or ICMP Flood Attacks, where the source sends a bunch of ICMP requests (orig_bytes), but the target doesn’t really respond (resp_bytes is super low or zero).

```
DeviceNetworkEvents
| extend Source_IP_Country = tostring(geo_info_from_ip_address(LocalIP).country),
 Destination_IP_Country = tostring(geo_info_from_ip_address(RemoteIP).country),
 Direction = tostring(parse_json(AdditionalFields).direction), 
 orig_bytes = toint(parse_json(AdditionalFields).orig_bytes),
 resp_bytes = toint(parse_json(AdditionalFields).resp_bytes),
 duration = todouble(parse_json(AdditionalFields).duration)
// filtering by Inbound connections attempts where the IP is reported and there are difference between the received and the responded bytes
| where Direction has "In" and isnotempty(Source_IP_Country) and isnotempty(Destination_IP_Country) and resp_bytes != orig_bytes
| extend difference= abs(orig_bytes - resp_bytes)
| summarize by Source_IP_connection=LocalIP,Source_IP_Country, Destination_IP=RemoteIP, Destination_IP_Country,orig_bytes,resp_bytes,difference, Protocol, ActionType, duration, Direction
| order by duration
```
