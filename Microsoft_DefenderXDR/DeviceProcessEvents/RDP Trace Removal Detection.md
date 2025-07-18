**RDP Trace Removal Detection**

By analyzing login sequences, screen tile caches, clipboard data, and session memory, analysts can now reconstruct full attacker activity during Remote Desktop sessions—even if the adversary tries to cover their tracks. 
The following KQL Query helps to identify when a ransomware attack attempts to remove the mentioned evidence via script which will be identified as executed command.

```
DeviceProcessEvents
| where ProcessCommandLine has_all ("delete", "\\Software\\Microsoft\\Terminal Server Client\\Default") 
 or ProcessCommandLine has_all ("delete", "\\Software\\Microsoft\\Terminal Server Client\\Servers")
 or ProcessCommandLine has_all ("add", "\\Software\\Microsoft\\Terminal Server Client\\Servers")
| project Timestamp, DeviceName,DeviceId, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId
```
