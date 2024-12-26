**Detect sensitive and confidential files sent by Email**

To detect sensitive or confidential information sent by email from our users, I discovered that DefenderXDR is registering events when some user or services is reading files tagged or marked as sensitive. Basically, it has a "SensitiveFileRead" ActionType in the DeviceFileEvents table which indicates that a process on the monitored device has accessed a file classified as sensitive. This could include files with personally identifiable information (PII), intellectual property, or other data deemed sensitive based on the organization’s data protection policies or Microsoft’s predefined rules.
This event type is essential for tracking access to sensitive data, helping to identify potential data leakage or unauthorized access attempts. 
```
DeviceEvents
| where ActionType has "SensitiveFileRead"
| join kind=inner (EmailAttachmentInfo) on $left.FileName == $right.FileName
// Extend the information to know if the sensitivefile was sent to a different domain than the sender
| extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@")[1])
| extend SensitiveFileSentTo = iff(SenderDomain == RecipientDomain, "Same Domain", "Different Domain")
| project DeviceName, FileName, FolderPath, InitiatingProcessFileName,InitiatingProcessAccountName, InitiatingProcessAccountUpn,InitiatingProcessVersionInfoFileDescription, InitiatingProcessVersionInfoCompanyName, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, SensitiveFileSentTo, FileSent = FileName1
```
