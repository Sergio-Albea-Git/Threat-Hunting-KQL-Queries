**Detect External Sources scanning my exposed devices.md**

**Description:**  Detecting ExternalSource IP's that are scanning my exposed devices which helps me to identify if some IP's is triggering scans multiple times or in multiple devices.

```
DeviceNetworkEvents
// Filter on devices that have been scanned
| where ActionType == "InboundInternetScanInspected"
| project IP_Source_ScannerAttempt=LocalIP,Country_Source_ScannerAttempt=tostring(geo_info_from_ip_address(LocalIP).country), PublicScannedIP= RemoteIP,PublicScannedIP_country=tostring(geo_info_from_ip_address(RemoteIP).country), PublicScannedPort= RemotePort,DeviceName
```
