**Identities Bad Reputation ASN activities**

**Description**: This new query generates additional information using ASN/CIDR info from 'Firewall IP Lists @ Gyp the Cat dot Com' site (which takes data provided by other services and formats them) combined with a 'Bad ASN Rate/Reputation' source from the well-known source SpamHaus. As a result, it will show if some user sign-in attempt was trigger from a SenderIP address related to the mentioned ASN's and it can be filtered to just show the 'LoginSuccess' cases:

```
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
with (ignoreFirstRecord=true));
let Malicious_ASN= (externaldata (asn:string)['https://www.spamhaus.org/drop/asndrop.json']with(format="multijson"));
IdentityLogonEvents
| evaluate ipv4_lookup(CIDRASN, IPAddress , CIDR, return_unmatched=true)
| extend GeoIPData = geo_info_from_ip_address(IPAddress)
| where isnotempty( CIDR)
| extend asn_info = tostring(CIDRASN)
//| where ActionType has "LogonSuccess"
| join kind=inner (Malicious_ASN) on $left.asn_info == $right.asn
```
