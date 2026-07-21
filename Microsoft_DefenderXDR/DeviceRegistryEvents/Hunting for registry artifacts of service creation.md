**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service |

**Author:** Sergio Albea (05/06/2026)

---

**Hunting for registry artifacts of service creation**

This query helps to identify service creation events regardless of the tool/method used for service creation (even if the threat actors use the Windows API directly, without leaving any command line traces).
```
DeviceRegistryEvents
| where ActionType has "RegistryKeyCreated" and RegistryValueName contains "\\service\\" and (RegistryValueData has "ImagePath" or RegistryValueData has "ServiceDll")
```
