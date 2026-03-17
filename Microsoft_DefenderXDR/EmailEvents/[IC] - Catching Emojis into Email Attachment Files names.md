**[IC] - Catching Emojis into Email Attachment Files names**

| Technique ID | Title    |
| ---  | --- |
| T1036 | Masquerading |


| Author | Sergio Albea (16/03/2026)   |
| ---  | --- |

Attackers take advantage of the emojis because they help the content stand out and gets more attention than plain text. It not apply just to Email Subject if not that it also applies to Attachment Files which based on my experience, legitime file not use to have icons in their file names.For example:

- 📄Invoice.pdf
- 🔐Reset_Password.html
- 📦Delivery_Document.zip

This can help find:

- Suspicious files dropped on emails
- Files downloaded from phishing emails
- User-downloaded /opening scam files
- Payloads with social engineering names

```
// Sergio Albea 16-03-2026 ©️
EmailAttachmentInfo
| where Timestamp > ago(7d) and isnotempty(FileExtension) and isnotempty(FileName)
| extend Icons = extract_all(@"([\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}])", FileName)
| where isnotempty(Icons)
| join kind=inner (EmailEvents) on NetworkMessageId
| extend SenderIP = iff(isnotempty(SenderIPv4),SenderIPv4,SenderIPv6)
| extend geo_ip = tostring(geo_info_from_ip_address(SenderIP).country)
| project Timestamp,SenderDisplayName,SenderFromAddress,SenderIP,geo_ip,FileName,FileExtension,RecipientEmailAddress,Icons
| order by Timestamp desc
```
