**Detecting potential CA policy bypass by privileged accounts via private browser sessions**

When two accounts from the same Entra tenant are signed into the same browser app, the device authentication (the PRT) belonging to the primary account is implicitly applied to the second account. That means the second account can inherit device-based Conditional Access, effectively bypassing intended device checks and weakening protection for privileged accounts.

Based on this behavior, I created a KQL query that detects any account assigned a privileged role signing in with private/incognito browser sessions on a device where potentially another account is already signed in — a pattern that helps to detect the mentioned PRT/device-trust bypass. Even lower-privileged accounts are concerning when they browse in private mode so I am not filtering by just admin ones. However, to target specific roles, add:
| 𝘸𝘩𝘦𝘳𝘦 𝘵𝘰𝘴𝘵𝘳𝘪𝘯𝘨(𝘈𝘴𝘴𝘪𝘨𝘯𝘦𝘥𝘙𝘰𝘭𝘦𝘴) 𝘤𝘰𝘯𝘵𝘢𝘪𝘯𝘴 "𝘢𝘥𝘮𝘪𝘯"

```
DeviceProcessEvents
|where isnotempty(AccountUpn) and FileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| extend Navigation_Mode= iif(ProcessCommandLine has_any("--incognito","--inprivate","-private","-private-window"),"🚨Private","Normal")
| join kind=inner (IdentityInfo) on $left.AccountUpn == $right.AccountUpn
| summarize Navigation_Mode=make_set(Navigation_Mode),make_set(AccountUpn),Distinct_Upn=dcount(AccountUpn),AssignedRoles=make_set(AssignedRoles),Potential_Case=dcount(Navigation_Mode) by DeviceName
| where Potential_Case > 1 and Distinct_Upn > 1 and (tostring(AssignedRoles) != "[]")
//| where tostring(AssignedRoles) contains "admin" 
```
