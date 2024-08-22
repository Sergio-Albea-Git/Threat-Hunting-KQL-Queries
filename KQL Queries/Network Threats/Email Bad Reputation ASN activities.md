**Email Bad Reputation ASN activities**

**Description**: This new query generates additional information using ASN/CIDR info from 'Firewall IP Lists @ Gyp the Cat dot Com' site (which takes data provided by other services and formats them) combined with a 'Bad ASN Rate/Reputation' source from the well-known source SpamHaus. As a result, it will show if some email was sent from a SenderIP address related to the mentioned ASN's and if the message is delivered into Inbox Folder:

```
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
with (ignoreFirstRecord=true));
let Malicious_ASN= (externaldata (asn:string)['https://www.spamhaus.org/drop/asndrop.json']with(format="multijson"));
EmailEvents
| evaluate ipv4_lookup(CIDRASN, SenderIPv4, CIDR, return_unmatched=true)
| extend GeoIPData = geo_info_from_ip_address(SenderIPv4)
| where isnotempty( CIDR)
| extend asn_info = tostring(CIDRASN)
| where DeliveryLocation has "Inbox"
| join kind=inner (Malicious_ASN) on $left.asn_info == $right.asn
| project Timestamp, SenderFromAddress,SenderMailFromAddress, SenderDisplayName, SenderMailFromDomain, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction,DeliveryLocation, ThreatTypes, CIDR, CIDRASNName, asn_info, asn
```
