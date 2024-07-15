** Detecting Malicious ISP's**
** Description:** During my  "holidays", I discovered some suspicious ISP in the country where I am and I was wondering if I could detect them using Defender XDR, and indeed, it is possible.
Instead of blocking multiple IP's one by one, which are detected as malicious and consume significant work time, why not block malicious ISP's if all connection attempts from it are malicious ? 
The following query shows the list of ISP's from where there are sign-in attempts, indicating which ones are suspicious and which are not (ISPRate column).
If you discover ISP's with only suspicious IP's, I recommend blocking connections coming from these ISP's.
On the other hand, if you identify some ISP's that are valid, you can "whitelist" them using the line --> | where ISP !in ("vodafone btw") and Location !in ("IR").
Also, be cautious if a provider uses the same name to provide service in multiple countries; usually, their ISP name will have some differences between locations.

```
IdentityLogonEvents
| where Timestamp > ago(1d)
| extend ISPRate = iif(FailureReason contains "locked", "Suspicious","valid")
| where ISP !in ("vodafone btw ") and Location !in ("IT")
| project ISP, Location, IPAddress, AccountDomain, LogonType, FailureReason, ISPRate
| order by ISP
```
