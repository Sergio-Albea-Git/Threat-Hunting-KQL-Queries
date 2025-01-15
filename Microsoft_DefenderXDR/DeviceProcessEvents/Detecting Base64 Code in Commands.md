**Detecting Base64 Code in Commands**

This KQL Query is oriented to detect strings added into executed command lines which are base64coded. After it, it decoded the corresponding string and show the results decoded.
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
| where isnotempty(DecodedString)
| distinct DeviceName,InitiatingProcessCommandLine,LongestWord,DecodedString
```
