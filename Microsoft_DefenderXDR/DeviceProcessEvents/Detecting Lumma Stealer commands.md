**Detecting Lumma Stealer commands**

One of the techniques used to distribute the Lumma Stealer malware is via command lines using the native Windows application mshta which is an HTML tool for executing scripts. This KQL Query helps to identify commands that use the aforementioned application and also those that use the
application and also those that use powershell and encode the malicious code in base64.

```
DeviceFileEvents
| extend CommandWords = split(InitiatingProcessCommandLine, " ") // Split the command into words
| extend Word1 = CommandWords[0], // First word
 Word2 = CommandWords[1], // Second word
 Word3 = CommandWords[2], // Third word
 Word4 = CommandWords[3], // Fourth word
 Word5 = CommandWords[4] 
| extend LongestWord = case(
 strlen(Word1) >= strlen(Word2) and strlen(Word1) >= strlen(Word3) and strlen(Word1) >= strlen(Word4) and strlen(Word1) >= strlen(Word5), Word1,
 strlen(Word2) >= strlen(Word1) and strlen(Word2) >= strlen(Word3) and strlen(Word2) >= strlen(Word4) and strlen(Word2) >= strlen(Word5), Word2,
 strlen(Word3) >= strlen(Word1) and strlen(Word3) >= strlen(Word2) and strlen(Word3) >= strlen(Word4) and strlen(Word3) >= strlen(Word5), Word3,
 strlen(Word4) >= strlen(Word1) and strlen(Word4) >= strlen(Word2) and strlen(Word4) >= strlen(Word3) and strlen(Word4) >= strlen(Word5), Word4,
 Word5 // Default case if Column5 is the longest
)
| extend tostring(LongestWord)
| extend DecodedBytes = base64_decode_tostring(LongestWord)
| extend DecodedString = tostring(DecodedBytes)
| where DecodedString contains "mshta" or InitiatingProcessCommandLine contains "mshta"
| distinct DeviceName,InitiatingProcessCommandLine,LongestWord,DecodedString
```
