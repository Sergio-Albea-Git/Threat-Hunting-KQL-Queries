**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1036.008 | Masquerading: Masquerade File Type |

**Author:** Sergio Albea (11/06/2026)

---

**Detect Shebang code inside files with unusual extensions**

**Description:** Shebangs (#!) are native to Unix-like operating systems (macOS and Linux). Standard Windows consoles (Command Prompt and PowerShell) do not natively use them. However, they do work on Windows when using tools such as the Python Launcher, Git Bash, Cygwin, or Unix-like environments such as WSL. In simple terms, a Shebang tells the operating system which interpreter should execute a script. For example: #!/usr/bin/python3

Distinct scripts can not look dangerous based on their extension, but they are still executable files. In environments with macOS, Linux, WSL, Git Bash or Python Launcher, this can help to identify scripts renamed to hide their real purpose.

```
DeviceFileEvents
| extend AF=parse_json(AdditionalFields) | where tostring(AF.FileType) == "Shebang" 
| where FileName has_any (".txt", ".log", ".dat", ".tmp", ".conf", ".jpg", ".png", ".pdf") 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```
