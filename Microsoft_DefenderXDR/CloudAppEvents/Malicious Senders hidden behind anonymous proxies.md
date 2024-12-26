**Malicious Senders hidden behind anonymous proxies**

I had pending to have a deep view into the CloudAppEvents table and finally I had some time over the weekend to have a look around.
I will have an interesting work to look for the cases where the attackers are using Anonymous Proxy. To start, let's catch some "GhostHackers" that thinks that being hidden behind a proxy, they will not be hunted sending malicious emails.

```
CloudAppEvents
| where IsAnonymousProxy == 1
| where Application contains "Exchange"
| where ActionType contains "TIMailData-Inline"
| where RawEventData.DeliveryAction contains "Delivered"
| project IPAddress, CountryCode, City, ISP, RawEventData.Subject,RawEventData.P2Sender, RawEventData.DeliveryAction, RawEventData.Verdict, ActionType, Application
```
