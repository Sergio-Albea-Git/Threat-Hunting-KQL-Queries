**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment |

**Author:** Sergio Albea (11/06/2026)

---

**Detect Shebang File Types received via Email**

**Description:** Shebangs (#!) are native to Unix-like operating systems (macOS and Linux). Standard Windows consoles (Command Prompt and PowerShell) do not natively use them. However, they do work on Windows when using tools such as the Python Launcher, Git Bash, Cygwin, or Unix-like environments such as WSL. In simple terms, a Shebang tells the operating system which interpreter should execute a script. For example: #!/usr/bin/python3

The first thing that came to my mind was to hunt for cases where these kinds of files were received via email, and yes, I quickly found a few Python and ECM-related examples.

```
let ShebangFiles = DeviceFileEvents | extend AF=parse_json(AdditionalFields) | where tostring(AF.FileType) == "Shebang" and  isnotempty(SHA256)
| project FileTimestamp=Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA256, FileActionType=ActionType, FileInitiatingProcess=InitiatingProcessFileName, FileInitiatingCommandLine=InitiatingProcessCommandLine, FileType=tostring(AF.FileType);
ShebangFiles
| join kind=inner EmailAttachmentInfo on $left.SHA256 == $right.SHA256
```
