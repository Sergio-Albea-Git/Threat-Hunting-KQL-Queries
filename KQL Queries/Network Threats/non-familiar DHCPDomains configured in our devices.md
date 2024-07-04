**Detecting non-familiar DHCPDomains configured in our devices**

**Description**:As far as my users are managing sensible or critical information, I am not really happy when their local device configuration are modified and their network rely on airports, hotels, or the nearest coffee shop's Wi-Fi.
This Query review if the TCPIP register is modified and it DHCP Domain is managed by a non-trusted/known network. It would help me to restrict their access to enterprise data until I am 100% sure they are using a VPN or back to enterprise DHCP Domain.

```
DeviceRegistryEvents
| where RegistryKey contains "tcpip"
| where RegistryValueName contains "dhcpdomain"
// to reduce the number of false positive, I moved out localIPs, results with "." to reduce the number of local home routers and specific country
| where RegistryValueData !contains "192." and RegistryValueData contains "." and RegistryValueData !endswith ".es"
```
