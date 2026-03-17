**[IC] - Catching Emojis into File Names**

| Technique ID | Title    |
| ---  | --- |
| T1036 | Masquerading |


| Author | Sergio Albea (16/03/2026)   |
| ---  | --- |

[IC] - Catching Emojis into File Names
Attackers do not only use emojis in the subject. Sometimes they also use them in the file name itself to make the file look more attractive or legitimate. Based on my experience, I am not expecting legitimate files names with icons so it can be an interesting case to easily convert the hunting into a detection. For example:

- 📄Invoice.pdf
- 🔐Reset_Password.html
- 📦Delivery_Document.zip

This can help find:

- Suspicious files dropped on disk
- Files downloaded from phishing emails
- User-downloaded scam files
- Payloads with social engineering names

```
// Sergio Albea 16-03-2026 ©️
DeviceFileEvents
| where Timestamp > ago(7d)
| where isnotempty(FileName)
| extend Icons = extract_all(@"([\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}])", FileName)
| where isnotempty(Icons)
| project InitiatingProcessRemoteSessionIP,MD5,DeviceName,FileName,FolderPath,InitiatingProcessFileName,Icons,ReportId,DeviceId
```
