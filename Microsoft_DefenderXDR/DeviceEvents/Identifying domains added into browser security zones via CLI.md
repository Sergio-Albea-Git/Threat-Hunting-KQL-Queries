**Identifying domains added into browser security zones via CLI**

**Description:** The ZoneMap key under Internet Settings is used to define security zones for specific domains. 
By setting a value under ZoneMap\Domains\, you are configuring how Windows handles security and permissions for that domain so it is really helpful to identify if some site has been added via cli manually or by some malicious script to whitelist some domains and bypass some defense.


```
DeviceEvents
| where AdditionalFields contains "ZoneMap"
| extend command = split(AdditionalFields, ' ')
| mv-expand command
| where command contains "ZoneMap"
| extend command = tostring(command)
| extend command = split(command, '\\')
| mv-expand command | extend tostring(command) | where command endswith "'"
| extend CleanedKey = replace(@"'", "", command)
// in case you have trusted domains allowed to be whitelisted, add them in the next line
| where CleanedKey !in ("google.com")
| distinct Timestamp, DeviceName, AdditionalFields, CleanedKey, ReportId
```
