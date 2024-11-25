**Rating ISPs to detect potential malicious domains sending threats**

**Description:** This latest query is oriented to email threats and allows you to rate ISPs to detect:

- ISPs that are using multiple domains to send you threat emails.
- ISPs and domains with a high percentage of malicious emails, and to verify if any were delivered into Inbox folders.
-ISPs using multiple different IP addresses to send you threats.
...and more!

```
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']with (ignoreFirstRecord=true));
EmailEvents
| evaluate ipv4_lookup(CIDRASN, SenderIPv4, CIDR, return_unmatched=true)
| extend GeoIPData = tostring(geo_info_from_ip_address(SenderIPv4).country)
| summarize Different_IPs=make_set(SenderIPv4), Countries= make_set(GeoIPData), make_set(CIDR), make_set(SenderFromDomain), Total_different_IPs=dcount(SenderIPv4) ,Total_emails = count(),make_set(ThreatTypes),Delivered_on_Inbox= countif(DeliveryLocation has "Inbox/folder"), Email_Threat= count(isnotempty(ThreatTypes)),
Email_Valid = count( isempty(ThreatTypes)) by GeoIPData, CIDR, CIDRASNName
| extend SuspiciousRatio = Email_Threat * 1.0 / Total_emails, ValidRatio = Email_Valid * 1.0 / Total_emails
| extend SuspiciousPercentage = SuspiciousRatio * 100, ValidPercentage = ValidRatio * 100
| order by Email_Threat
| project CIDRASNName,set_SenderFromDomain, set_CIDR, Different_IPs, Countries,Total_different_IPs, set_ThreatTypes,Total_emails, Delivered_on_Inbox, Email_Threat, Email_Valid, SuspiciousPercentage, ValidPercentage
```
