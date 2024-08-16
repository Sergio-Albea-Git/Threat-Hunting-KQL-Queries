**Classifying HTTP Status Code and detecting possible Threatss**

**Description**: I decided to create a table with extended information about the potential threats associated with HTTP status code.
This allows me to quickly work with other KQL queries to identify potential threats.
Consider this KQL query as a "Pivot Table" for multiple queries that can be triggered based on your criteria.

```
let status_codes = externaldata(statuscode: string, Type_code: string, Description:string, Possible_Threat:string)[@"https:// raw.githubusercontent.com /Sergio-Albea-Git/-Defender-XDR-/main/Security-Lists/status_code.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceNetworkEvents
| extend status_code = parse_json(AdditionalFields).status_code
| extend SiteIPCountry = geo_info_from_ip_address(RemoteIP).country
| extend Method = parse_json(AdditionalFields).method
| extend Site = parse_json(AdditionalFields).referrer
| extend status_code = parse_json(AdditionalFields).status_code
| extend host = parse_json(AdditionalFields).host
| extend status_code = tostring(status_code)
| extend Site = tostring(Site)
| extend Method = tostring(Method)
| extend SiteIPCountry = tostring(SiteIPCountry)
| where isnotempty(SiteIPCountry)
| where isnotempty(status_code)
| where isnotempty(Site)
// the next line depends on your criteria, just removing some cases to have the results that I am looking for
| where Site !has "www.google." or Site !has "support.amd.com"
| lookup kind=inner ( status_codes) on $left.status_code == $right.statuscode
// you can add other fields in the project list such as Method or other ones into AdditionalFields but the number of results will increase considerably
| summarize make_list(status_code),make_list(DeviceName),Count = count() by RemoteIP, SiteIPCountry, Site,Type_code, Description, Possible_Threat
| order by Count 
```
