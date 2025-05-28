**Detect suspicious files dropped into Public Folder**

One of the key behaviors often observed during ransomware attacks includes dropping ransom notes in the C:\Users\Public folder. These actions are designed to ensure that all users on the infected machine are made aware of the compromise.
Fortunately, if your environment monitors for file creation events in these paths, you may be able to detect such activities promptly. This can enable quick response actions—such as alerting, isolating the device (using Detection Rules Actions), or initiating automated investigation. 
I recommend you to execute this KQL query to see if you have some false positive to whitelist them as I have with .lnk files ( basically browser shortcuts)
```
DeviceEvents
| where FolderPath contains "Users\\Public" and FileName !endswith ".lnk"
| distinct DeviceName, ActionType, FileName, FolderPath 
```
