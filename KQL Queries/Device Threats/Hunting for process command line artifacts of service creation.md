**Hunting for process command line artifacts of service creation**

Threat actors might use command line utilities to create a services.

```
DeviceProcessEvents
| where ActionType has "ProcessCreated" and FileName has "sc.exe" and ProcessCommandLine contains "creat"
```
