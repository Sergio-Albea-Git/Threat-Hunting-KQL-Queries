**Review required outbound connections to work with Defender for Cloud Apps**

Microsoft has a new requirement for Cloud Apps to ensure service quality and prevent the interruption of some services and needs immediate Action by April, 21 2025. It is related to update your firewall rules to allow outbound traffic on port 443 for the corresponding IP addresses and URLs. 



Therefore, there are an important number of URLs and IPs thats needs to be allowed to establish communications from our devices to outside. 

The KQL Query of this week should help you to detect if there are some issue with the listed URL's and also you can add the range of IP's that applies to your case depending on the location of your DefenderXDR Tenant. (Verify your location on System > Settings > Cloud Apps > System > About > Datacenter)

```
DeviceNetworkEvents
| where  ActionType !has "ConnectionSuccess" and RemotePort == 443
| where 
    ipv4_is_in_range(RemoteIP, "3.107.219.0/24") or
    ipv4_is_in_range(RemoteIP, "13.107.227.0/24") or
    ipv4_is_in_range(RemoteIP, "13.107.228.0/24") or
    ipv4_is_in_range(RemoteIP, "13.107.229.0/24") or
    ipv4_is_in_range(RemoteIP, "150.171.97.0/24") or
    RemoteIP in~ ("13.80.125.22", "40.74.1.235", "40.74.6.204", "40.81.156.154", 
                  "40.81.156.156", "51.143.58.207", "52.137.89.147", 
                  "52.183.75.62", "20.0.210.84", "20.90.9.64") or
    RemoteUrl has "cdn.cloudappsecurity.com" or
    RemoteUrl has "cdn-discovery.cloudappsecurity.com" or
    RemoteUrl has "adaproddiscovery.azureedge.net" or
    RemoteUrl has "dev.virtualearth.net" or
    RemoteUrl has "flow.microsoft.com" or
    RemoteUrl has "static2.sharepointonline.com" or
    RemoteUrl has "discoveryresources-cdn-prod.cloudappsecurity.com" or
    RemoteUrl has "discoveryresources-cdn-gov.cloudappsecurity.us" or
    RemoteUrl endswith  ".s-microsoft.com" or
    RemoteUrl endswith  ".msecnd.net" or
    RemoteUrl endswith  ".blob.core.windows.net"
| project Timestamp, DeviceName,LocalIP,Outbound_IP_connection_to= RemoteIP, RemotePort,Outbound_URL_connection_to= RemoteUrl,Result_Connection_Attempt=ActionType, Protocol
| order by Timestamp desc
```
