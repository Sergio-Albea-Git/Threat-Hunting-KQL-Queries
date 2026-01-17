**[IA] - Threat Intelligence Feed Evaluation based on URL IOCs**

| Technique ID | Title    |
| ---  | --- |
| T1566.002 | Phishing: Spearphishing Link  |


| Author | Sergio Albea (12/01/2026)   |
| ---  | --- |

TIFCE (Threat Intelligence Feed Content Evaluation) is a simple way to measure if a TI feed is actually useful based on four things — uniqueness, real matches, confirmed maliciousness, and activity.
🚨 TIFCE allows using one detection per IOC type (URLs, domains, file hashes) instead of dozens of rules per feed, keeping detections clean, centralized, and easy to maintain.
In addition, if you rely on threat intelligence for detection, it can be a good solution to how to evaluate current or new TI feeds.

```//Sergio Albea 12-01-2026 TIFCE https://zenodo.org/records/18208974
let BotvrijRAW = externaldata(Url: string)[@'https://www.botvrij.eu/data/ioclist.domain']| extend Url = substring(Url, 0, indexof(Url, '#'))| where isnotempty(Url) or Url != ''| project TIFeed= 'BotvrijRAW',IOC= Url,Reference = 'https://www.botvrij.eu/data/ioclist.domain';
let montysecurity =externaldata(URLS:string)[@'https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/all.txt'] with (format='csv') | project TIFeed= 'montysecurity',IOC= URLS,Reference = 'C2IntelFeeds';
 let PhishuntURLs = externaldata (Url: string) ['https://phishunt.io/feed.txt']| where Url !in ('https://www.google.com/chrome/','https://www.microsoft.com/en-us/microsoft-teams/log-in')| project TIFeed= 'PhishuntURLs',IOC= Url,Reference = 'https://hole.cert.pl/domains/v2/domains.txt';
 let C2IntelFeeds =externaldata(URLS:string)[@'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/refs/heads/master/feeds/domainC2swithURLwithIP-30day-filter-abused.csv']with (format='csv') | where URLS !startswith '#' | project TIFeed= 'C2IntelFeeds',IOC= URLS,Reference = 'C2IntelFeeds';
 let Openphish =externaldata(URLS:string)[@'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt']with (format='csv') | project TIFeed= 'OpenPhish',IOC= URLS,Reference = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
 let URL_TweetFeedMonth =externaldata(DateUTC: datetime,SourceUser: string,Type: string,Value: string,Tags: string,Tweet: string)[@'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv']with (format='csv') | where Type has 'url' | project TIFeed= 'URL_TweetFeedMonth',IOC= Value,Reference='https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv';
 //unify TIFeeds IOC List
 let URL_IOCs = union Openphish,C2IntelFeeds,URL_TweetFeedMonth,BotvrijRAW,PhishuntURLs;
 //ℹ️ Remove the comments of the 2 following lines to get a summary of the IOCs present on distinct TI Feeds
 //URL_IOCs | summarize dcount(TIFeed),make_set(TIFeed) by IOC | order by dcount_TIFeed
//
   EmailUrlInfo   | where Timestamp > ago(30d) | join kind=inner (URL_IOCs) on $left.Url == $right.IOC
    | join kind=inner (EmailEvents) on NetworkMessageId | extend IPSender = iff(isnotempty( SenderIPv4),SenderIPv4,SenderIPv6) | extend Time_ = format_datetime( Timestamp, 'yyyy-MM-dd') 
    | summarize by Time_,TIFeed,IOC,DeliveryLocation, Url,Subject,IPSender, SenderMailFromDomain,Reference
```
