**Devices with external RDP connections.md**

**Description:** This query identifies devices into DeviceEvents table that are initiating RDP connections and provides the location of the remote IP addresses. 
DeviceEvents table has a column called 'LocalIP' which can be confusing but it also includes RemoteIPs. I excluded the entries without info about the location of the IP (which means are potentially Local IPs). As optional, you can add a line to exclude “whitelisted” location such as :' | where location !contain "Spain" '
