**IOCs for SmartApeSG fake browser update leads to NetSupport RAT and StealC**

Based on the post below posted by Palo Alto Networks Unit 42, I created a quick KQL query to detect potential matches with some of the IOCs related to distribution of hashtag#NetSupportRAT and hashtag#StealC malware.
In some parts of the query, I use broader conditions instead of specifying exact DLL names or remote IP addresses. This approach helps extend detection capabilities in case the threat actor modifies file names or switches to a similar IP.

```
let URL_IOCs =DeviceNetworkEvents 
| extend method = tostring(parse_json(AdditionalFields).method), uri = tostring(parse_json(AdditionalFields).uri)
| where (method has "POST" and ("RemoteIP" startswith "62.164.130" or uri endswith "dll")) or RemoteUrl contains "cinaweine" or RemoteIP startswith "194.180.191" or RemoteUrl contains "poormet";
let FILE_IOC = DeviceFileEvents | where SHA256 has "47f59d61beabd8f1dcbbdd190483271c7f596a277ecbe9fd227238a7ff74cbfc" or SHA256 has "b71f07964071f20aaeb5575d7273e2941853973defa6cb22160e126484d4a5d3" or SHA256 contains "e9eb934dad3f87ee581df72af265183f86fdfad87018eed358fb4d7f669e5b7d" or FileName has "rtworkq.dll" or FileName has "misk.zip" or (FileName startswith "update " and FileName endswith "js") ;
let DLL_IOC = DeviceImageLoadEvents | where SHA256 has "021bb478b704abb95ac2040061b7d47d8e4b491e6d2633adb010c3b8b08bb4f4";
union URL_IOCs, FILE_IOC, DLL_IOC
```
