**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service |

**Author:** Sergio Albea (13/12/2024)

---

**Hunting for process command line artifacts of service creation**

Threat actors might use command line utilities to create a services.

```
DeviceProcessEvents
| where ActionType has "ProcessCreated" and FileName has "sc.exe" and ProcessCommandLine contains "creat"
```
