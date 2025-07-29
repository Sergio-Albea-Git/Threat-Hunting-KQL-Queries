**Detect Attempts to modify Amcache.hve or SYSTEM files**

**Description:**  Amcache.hve is a Windows registry file that logs details about executed programs, including file paths, hashes, timestamps, and metadata. It helps reconstruct what was run on a system—even if the original file is gone. 
On the other hand, Shimcache is a memory-resident registry artifact that records executables seen or run by the system. It stores file paths and last modified timestamps, making it useful for tracking historical program execution—even after deletion.
Attackers aware of forensic techniques could try to delete or alter these files to remove the evidences of their attacks:

Deleting or wiping Amcache.hve
Overwriting or tampering with the SYSTEM hive to destroy Shimcache
Using tools like SDelete, cipher /w:, or direct registry access to tamper logs

That’s why it’s critical to monitor for these kinds of actions in Defender XDR or Microsoft Sentinel environments using KQL.

```
DeviceFileEvents 
| where (FileName contains "SYSTEM" and FolderPath contains "C:\\Windows\\System32\\config\\") or (FileName has "Amcache.hve")
| project Timestamp, DeviceName,DeviceId, FileName, FolderPath, ActionType, InitiatingProcessFileName, ReportId
```
