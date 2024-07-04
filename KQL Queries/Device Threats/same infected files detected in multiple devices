**Find devices where multiple files were executed and they were detected as infected**

**Description:** This query helped me to identify devices where users are executing multiple infected files from the 
same device and contact them before it antivirus cannot respond to a specific new threat. The fileNames of the infected
files are grouped which helps to see what type of files are using. 🕷 

DeviceEvents
| where ActionType contains "antivirusdetection"
| summarize ['FileNames']=make_set(FileName), total= count() by SHA1,SHA256, DeviceName, ActionType
| where total > 2
| sort by total
