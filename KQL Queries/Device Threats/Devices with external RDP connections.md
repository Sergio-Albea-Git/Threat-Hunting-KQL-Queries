**Devices with external RDP connections**

**Description:** This query identifies devices into DeviceEvents table that are initiating RDP connections and provides the location of the remote IP addresses. 
DeviceEvents table has a column called 'LocalIP' which can be confusing but it also includes RemoteIPs. I excluded the entries without info about the location of the IP (which means are potentially Local IPs). As optional, you can add a line to exclude “whitelisted” location such as :' | where location !contain "Spain" '

```
DeviceEvents
| where ActionType contains "RemoteDesktopConnection"
| extend Country_IP = tostring(geo_info_from_ip_address(LocalIP).country)
| where isnotempty(Country_IP)
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, Country_IP,ReportId, DeviceId
```
