**Identifying File Exfiltration via RDP Sessions**

**Description:** The following KQL query focuses on detecting cases where files are created, modified, or otherwise accessed via RDP from another computer. Its main objective is to verify whether, during an RDP session, the connection has mapped a local disk or other redirected device — allowing us to easily identify potential cases of data exfiltration through RDP file transfer.

```
DeviceFileEvents
| where FolderPath startswith "\\\\tsclient" and isnotempty(InitiatingProcessRemoteSessionIP)
| extend geo_info= tostring(geo_info_from_ip_address(InitiatingProcessRemoteSessionIP).country)
| project Timestamp,RemoteIP=InitiatingProcessRemoteSessionIP,geo_info,External_Device=InitiatingProcessRemoteSessionDeviceName,DeviceId,Connected_to=DeviceName, ActionType, FileName, FolderPath,InitiatingProcessVersionInfoFileDescription,RequestAccountName, RequestAccountDomain, IsInitiatingProcessRemoteSession, InitiatingProcessSessionId,ReportId
```
