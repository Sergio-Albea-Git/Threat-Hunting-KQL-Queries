**Monitoring potential sign-in Attempts from Airport Networks**

**Description:** This query identifies potential connections from airport perimeters, which can help us identify bad actors using open WIFI's to trigger different attacks.
In addition, this information can help to identify travelling users, which can enrich alerts or incidents related to unknown sign-in attempts properties or tokens.

```
let Airport_Data = externaldata(AirportName:string, maxLatitude: decimal, minLatitude:decimal, maxLongitude:decimal, minLongitude:decimal,iata:string, country: string,maxlatindicator:int)[@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/refs/heads/main/Security-Lists/Airport_polygon.csv"] with (format="csv", ignoreFirstRecord=True);
AADSignInEventsBeta
| extend Latitude0 = todecimal(Latitude), Longitude0 = todecimal(Longitude)
| extend IntegerPart = toint(Latitude0)
| join kind=inner   (Airport_Data) on $left.IntegerPart == $right.maxlatindicator
| where Latitude0 > minLatitude and Latitude0 < maxLatitude and Longitude0 > minLongitude and Longitude0  < maxLongitude
| summarize make_set(AirportName),  make_set(country),dcount(AirportName) by AccountDisplayName, ErrorCode
```
