**Hunting for registry artifacts of service creation**

This query helps to identify service creation events regardless of the tool/method used for service creation (even if the threat actors use the Windows API directly, without leaving any command line traces).
```
DeviceRegistryEvents
| where ActionType has "RegistryKeyCreated" and RegistryValueName contains "\\service\\" and (RegistryValueData has "ImagePath" or RegistryValueData has "ServiceDll")
```
