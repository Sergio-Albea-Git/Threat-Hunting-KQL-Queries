**Potential commands executed by a powerShell.exe renamed**

PowerShell is a trusted Microsoft tool that attackers can misuse by renaming its executable file to hide their actions and deliver threats. The following query, detect cli common commands to identify the mentioned executions by a renamed Powershell.
```
DeviceProcessEvents
| where   ProcessCommandLine !contains "powershell"  
| where  ProcessCommandLine !contains "pwsh"
| where  ProcessCommandLine contains "-NoProfile" or ProcessCommandLine contains "-ExecutionPolicy" or  ProcessCommandLine contains "Invoke-Expression" 
| project DeviceName, FileName,ActionType, ProcessVersionInfoOriginalFileName, ProcessCommandLine, ProcessRemoteSessionIP
```
