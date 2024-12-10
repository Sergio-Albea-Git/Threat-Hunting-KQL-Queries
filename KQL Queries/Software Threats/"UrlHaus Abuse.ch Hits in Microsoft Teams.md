**UrlHaus Abuse.ch Hits in Microsoft Teams**

This Query is oriented to identify Malicious URL sent via Microsoft Teams and detect possible hits.

```
//UrlHaus Abuse.ch Hits in Microsoft Teams
let URLHausOnlineRAW = externaldata (UHFeed:string) ["https:// urlhaus.abuse.ch /downloads/csv_online/"] with(format="txt")
| where UHFeed !startswith "#"
| extend UHRAW=replace_string(UHFeed, '"', '')
| project splitted=split(UHRAW, ',')
| mv-expand id=splitted[0], dateadded=splitted[1], UHUrl=splitted[2], UHurl_status=splitted[3], UHlast_onlin=splitted[4], UHthreat=splitted[5], UHtags=splitted[6], UHLink=splitted[7], UHReporter=splitted[8]
| extend UHUrl = tostring(UHUrl);
 CloudAppEvents 
| where Application has "Microsoft Teams"
| extend MessageURLs = tostring(todynamic(RawEventData).MessageURLs)
| extend MessageURLs_ = substring(MessageURLs, 2, strlen(MessageURLs) - 4)
| join kind=inner URLHausOnlineRAW on $left.MessageURLs_ == $right.UHUrl
```
