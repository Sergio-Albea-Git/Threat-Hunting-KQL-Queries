**[IA] - Threat Intelligence Feed Evaluation based on FileHashes IOCs**

| Technique ID | Title    |
| ---  | --- |
| T1566.001 |Spearphishing Attachment |

| Author | Sergio Albea (12/01/2026)   |
| ---  | --- |

TIFCE (Threat Intelligence Feed Content Evaluation) is a simple way to measure if a TI feed is actually useful based on four things — uniqueness, real matches, confirmed maliciousness, and activity.
🚨 TIFCE allows using one detection per IOC type (URLs, domains, file hashes) instead of dozens of rules per feed, keeping detections clean, centralized, and easy to maintain.
In addition, if you rely on threat intelligence for detection, it can be a good solution to how to evaluate current or new TI feeds.
```
//Sergio Albea 12-01-2026 TIFCE https://zenodo.org/records/18208974
//TI Feeds Repositories
let MispHashes = externaldata(HashValue: string)['https://bazaar.abuse.ch/export/txt/sha256/recent/']with (format = 'csv',ignoreFirstRecord = true) | where HashValue !startswith '#' | project TIFeed= 'bazaar.abuse.ch',IOC= HashValue,Reference = 'https://bazaar.abuse.ch/export/txt/sha256/recent/'; 
let botvrij = externaldata(HashValue: string)['https://www.botvrij.eu/data/ioclist.sha256']with (format = 'csv',ignoreFirstRecord = true) | where HashValue !startswith '#' | extend Parts = split(HashValue, " ") | extend SHA256 = tostring(Parts[0])| project TIFeed= 'botvrij',IOC= SHA256,Reference = 'https://www.botvrij.eu/data/ioclist.sha256'; 
let FH_TweetFeedYear =externaldata(DateUTC: datetime,SourceUser: string,Type: string,Value: string,Tags: string,Tweet: string)['https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv']with (format='csv') | where Type has 'sha256' | project TIFeed= 'FH_TweetFeedYear',IOC= Value, Reference ='https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv';
//unify TIFeeds IOC List
let FH_IOCs = union MispHashes,botvrij,FH_TweetFeedYear; 
//ℹ️ Remove the comments of the 2 following lines to get a summary of the IOCs present on distinct TI Feeds
// FH_IOCs | summarize dcount(TIFeed),make_set(TIFeed) by IOC | order by dcount_TIFeed
//
EmailAttachmentInfo
| join kind=inner (FH_IOCs) on $left.SHA256 == $right.IOC
| join kind=inner (EmailEvents) on NetworkMessageId
```
