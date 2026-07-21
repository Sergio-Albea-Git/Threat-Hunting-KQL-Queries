**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1566 | Phishing |

**Author:** Sergio Albea (26/05/2026)

---

**Threat Hunting based on IOCs extracted from Security News and Reports**

**Description:** This query is oriented to identify IOCs observed into different Security websites and reports with the aim to identify quickly possible attacks reported from different sources. 
The TI Feed used, is based on a Claude AI Agent running daily collecting the mentioned indicators from the different sources.
Additional Info --> https://www.linkedin.com/pulse/use-ai-agents-enrich-generate-ti-feeds-based-security-sergio-albea-bxzze

```
let IOCFeed = externaldata(type:string,value:string,source_url:string,source_title:string,article_published_at:string,first_seen:string)
[@'https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/ee65c40ca7ed716a693c5c1b6cc779416e4571a1/Daily-IOCReportsCollection/iocs.csv']with(format='csv', ignoreFirstRecord=true);
//********Email Events**********
//Malicious URL
let Case0=IOCFeed| where type has 'url' | join kind=inner (EmailUrlInfo | extend URL = tostring(Url) | summarize by URL, UrlDomain,   UrlLocation) on $left.value == $right.URL | summarize by Case='Clicked URL',Insights=strcat('URL: ',URL),Asset_Affected=strcat('Type:',UrlDomain),value,type,source_title, source_url,article_published_at,first_seen;
//Malicious Email Address
let Case1_1=IOCFeed| where type has 'email' | join kind=inner (EmailEvents | extend sender = tostring(SenderMailFromAddress) | summarize by sender,Subject,RecipientEmailAddress) on $left.value == $right.sender
| summarize by  Case='Suspicious Sender',Insights=strcat('MailSubject: ',Subject),Asset_Affected=strcat('Recipient:',RecipientEmailAddress),value,type,source_title, source_url,article_published_at,first_seen;
let Case1_2=IOCFeed| where type has 'email' | join kind=inner (EmailEvents | extend recipient = tostring(RecipientEmailAddress) | summarize by recipient,Subject,RecipientEmailAddress) on $left.value == $right.RecipientEmailAddress
| summarize by  Case='Suspicious Sender',Insights=strcat('MailSubject: ',Subject),Asset_Affected=strcat('Recipient:',RecipientEmailAddress),value,type,source_title, source_url,article_published_at,first_seen;
//Malicioud Domain
let Case2_1=IOCFeed| where type has 'domain' | join kind=inner (EmailEvents | extend senderDomain = tostring(SenderFromDomain) | summarize by senderDomain,Subject,RecipientEmailAddress) on $left.value == $right.senderDomain
| summarize by Case='Email sent by Suspicious Domain',  Insights=strcat('Subject: ',Subject),Asset_Affected=strcat('Recipient:',RecipientEmailAddress),value,type,source_title, source_url,article_published_at,first_seen;
let Case2_2=IOCFeed| where type has 'domain' | join kind=inner (EmailEvents | extend senderDomain = tostring(SenderMailFromDomain) | summarize by SenderMailFromDomain,Subject,RecipientEmailAddress) on $left.value == $right.SenderMailFromDomain
| summarize by Case='Email sent by Suspicious Domain',  Insights=strcat('Subject: ',Subject),Asset_Affected=strcat('Recipient:',RecipientEmailAddress),value,type,source_title, source_url,article_published_at,first_seen;
//Malicious SenderIP
let Case3=IOCFeed| where type has 'ip' | join kind=inner (EmailEvents | summarize by senderIP = iff(isnotempty(SenderIPv4),SenderIPv4,SenderIPv6),Subject,RecipientEmailAddress) on $left.value == $right.senderIP
| summarize by Case='Email sent by Suspicious IP',  Insights=strcat('Subject: ',Subject),Asset_Affected=strcat('Recipient:',RecipientEmailAddress),value,type,source_title, source_url,article_published_at,first_seen;
// Malicious Attachment
let Case4_1=IOCFeed| where type has 'sha256' | join kind=inner (EmailAttachmentInfo | extend Attachment = tostring(SHA256) | summarize by SHA256, FileName,   FileType) on $left.value == $right.SHA256 | summarize by Case=' Attachment File',Insights=strcat('File: ',FileName),Asset_Affected=strcat('FileHash:',SHA256),value,type,source_title, source_url,article_published_at,first_seen;
//Device Network Connections
let Case5_1=IOCFeed| where type has 'ip' | join kind=inner (DeviceNetworkEvents | where ActionType has 'ConnectionSuccess' | summarize by RemoteIP,ActionType,DeviceName) on $left.value == $right.RemoteIP | summarize by Case='Suspicious Remote IP connection established',value,type,Insights=strcat('ActionType: ',ActionType),Asset_Affected=strcat('Device:',DeviceName),source_title, source_url,article_published_at,first_seen;
let Case5_2=IOCFeed| where type has 'ip' | join kind=inner (DeviceNetworkEvents | summarize by LocalIP,ActionType,DeviceName,RemoteIP) on $left.value == $right.LocalIP | summarize by  Case='Suspicious LocalIP connection established', value,type,Insights=strcat('Suspicious Local connection by:',LocalIP),Asset_Affected=strcat('Device:',DeviceName),source_title,source_url,article_published_at,first_seen;
// Device File Events
let Case6_1=IOCFeed| where type has 'sha256' | join kind=inner (DeviceFileEvents | extend Attachment = tostring(SHA256) | summarize by FileName,SHA256,DeviceName) on $left.value == $right.SHA256
| summarize by value,type,Insights=strcat('ActionType: ',FileName),Asset_Affected=strcat('Device:',DeviceName),source_title, source_url,article_published_at,first_seen;
let Case6_2=IOCFeed| where type has 'md5' | join kind=inner (DeviceFileEvents | extend Attachment = tostring(MD5) | project FileName,Attachment,DeviceName) on $left.value == $right.Attachment
| summarize by  Case='Suspicious File in Device',value,type,Insights=strcat('ActionType: ',FileName),Asset_Affected=strcat('Device:',DeviceName),source_title, source_url,article_published_at,first_seen;
let Case6_3=IOCFeed| where type has 'ip' | join kind=inner (EntraIdSignInEvents | extend IP_Ext = tostring(IPAddress) | summarize by IP_Ext,AccountDisplayName,Application,ErrorCode) on $left.value == $right.IP_Ext
| summarize by  Case='Sign-in attempt from Suspicious IP',value,type,Insights=strcat('ActionType: ',ErrorCode),Asset_Affected=strcat('User:',AccountDisplayName),source_title, source_url,article_published_at,first_seen;
// Suspicious Sign-in Attempts
let Case7=IOCFeed| where type has 'ip' | join kind=inner (DeviceProcessEvents | summarize by SHA256,FileName,DeviceName,InitiatingProcessRemoteSessionIP,AccountName) on $left.value == $right.InitiatingProcessRemoteSessionIP
| summarize by Case='Suspicious Process ', value,type,Insights=strcat('Executed:',FileName,' CMD:',InitiatingProcessRemoteSessionIP),Asset_Affected=strcat('Device:',DeviceName,' User:',AccountName),source_title,source_url,article_published_at,first_seen;
union Case0,Case1_1,Case1_2,Case2_1,Case2_2,Case3,Case4_1,Case5_1,Case5_2,Case6_1,Case6_2,Case6_3,Case7
```
