**Detect DefenderXDR services and features disabled on devices**

**Description:** This KQL Query is oriented to detect devices with DefenderXDR and associated features disabled which can be identified by the reg. keys as:

Enabled Value == 1
Disabled Value ==0

A bit confusing, If you enable these policy settings (RegistryValueData == 1), means that Windows Defender will not automatically take actions or report possible threats. On the other hand if is disabled (RegistryValueData == 0), Defender will automatically take action on all detected threats.

```
DeviceRegistryEvents
//If you enable these policy settings (RegistryValueData == 1), Windows Defender will not take actions or report possible threats.
//Windows Defender - Defender service itself.
//Spynet = Microsoft Active Protection Service is an online community that helps you choose how to respond to potential threats. This feature ensures the device checks in real time with the Microsoft Active Protection Service (MAPS) before allowing certain content to be run or accessed. If this feature is disabled, the check will not occur, which will lower the protection state of the device.
//Real-Time Protection = protection to scan for malware and other unwanted software. Once this has been disabled, it won’t scan anything of it.
| where RegistryKey == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" or RegistryKey == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\spynet" or RegistryKey == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Real-Time Protection"
| where RegistryValueData == 1
| distinct Timestamp, DeviceName, RegistryKey, RegistryValueName, PreviousRegistryValueData, RegistryValueData, IsInitiatingProcessRemoteSession
```
