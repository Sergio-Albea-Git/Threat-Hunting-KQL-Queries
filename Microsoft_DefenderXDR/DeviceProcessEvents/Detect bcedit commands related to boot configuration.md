**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1490 | Inhibit System Recovery |

**Author:** Sergio Albea (02/07/2025)

---

**Detect bcedit commands related to boot configuration**

This KQL query is designed to detect adversaries attempt to modify the boot configuration using bcdedit commands. Such changes are often used to disable recovery options or suppress error messages after encryption, helping ransomware persist stealthily across reboot.

```
DeviceProcessEvents
| where  ProcessCommandLine startswith "bcdedit"
```
