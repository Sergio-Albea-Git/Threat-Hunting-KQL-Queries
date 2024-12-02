**Detect PnP devices connected to my endpoint machines.md**

This query look for PnP devices connected or allowed into Endpoint machines. Basically, you can use the action types "PnpDeviceConnected" / "PnpDeviceAllowed" to have a list of PnP devices connected to your endpoints and it helps with some concerns such as:

1. Keeping an eye out for PnP devices like USB drives or external disks being connected to critical servers (like DC's, Exchange servers, or any machine with sensitive info).

2. If I’m handling sensitive info that shouldn’t be shared or printed, I want to make sure no printers are connected to my endpoints

3. Spotting unfamiliar devices from unknown vendors

4. Finding PnP devices that might be out of date and need attention

```
let connected = DeviceEvents
| where ActionType has "PnpDeviceConnected"
| extend ClassName = tostring(parse_json(AdditionalFields).ClassName),
 DeviceDescription = tostring(parse_json(AdditionalFields).DeviceDescription),
 ClassID = tostring(parse_json(AdditionalFields).ClassId),
 DevID0 = tostring(parse_json(AdditionalFields).DeviceId);
// Case1: Identify what is connected to a device | where DeviceName has ""
// Case2: Filter the type of PnP devices | where ClassName has "" 
// Case3 : Excluding specific PnP devices | where ClassName !in ("Monitor","Mouse");
DeviceEvents
| where ActionType has "PnpDeviceAllowed"
| extend DeviceInstanceId = tostring(parse_json(AdditionalFields).DeviceInstanceId),
 DriverProvider = tostring(parse_json(AdditionalFields).DriverProvider), 
 DriverDate = tostring(parse_json(AdditionalFields).DriverDate),
 DeviceUpdated = tostring(parse_json(AdditionalFields).DeviceUpdated),
 DriverVersion = tostring(parse_json(AdditionalFields).DriverVersion),
 DriverName = tostring(parse_json(AdditionalFields).DriverName)
| join kind=inner ( connected) on $left.DeviceInstanceId == $right.DevID0
// Case 4: Identify PnP devices from untrusted providers | where DriverProvider !in ("Microsoft","Logitech")
// Case 5: Identify non-updated PnP devices | where DeviceUpdated == "false"
| distinct DeviceName, ClassName, DeviceDescription, ClassID, DriverProvider, DriverDate, DeviceUpdated, DriverVersion, DriverName```
