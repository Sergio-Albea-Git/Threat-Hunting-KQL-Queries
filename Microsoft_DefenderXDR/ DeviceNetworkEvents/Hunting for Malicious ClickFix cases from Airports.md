**Hunting for Malicious ClickFix cases executed from Airports**

**Description**: A few months ago, I shared a post about the risks of users signing in from airport networks. These can easily be spoofed by malicious actors setting up fake Wi-Fi hotspots to harvest user credentials and other sensitive data.
Now, a new case has been reported involving users clicking on fraudulent Wi-Fi portals that trick them into executing a “connect” action to what appears to be a legitimate network.
These are essentially click-fix attacks, so I’m updating my KQL query to capture all types of DeviceEvents triggered from airport latitude and longitude locations. This should help identify a wider range of suspicious activities originating in such environments.

```
let Airport_Data = externaldata(AirportName:string, maxLatitude: decimal, minLatitude:decimal, maxLongitude:decimal, minLongitude:decimal,iata:string, country: string,maxlatindicator:int)[@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/refs/heads/main/Security-Lists/Airport_polygon.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceNetworkEvents
| where InitiatingProcessFileName has_any("powershell.exe", "curl.exe", "wget.exe", "Invoke-WebRequest")
| where RemoteUrl has_any(".png", ".html", ".htm") or RemotePort == 443 or RemotePort == 80
| extend geo = geo_info_from_ip_address(LocalIP) | extend Country  = tostring(geo.country), Latitude = tostring(geo.latitude),Longitude = tostring(geo.longitude)
| extend Latitude0 = todecimal(Latitude), Longitude0 = todecimal(Longitude)
| extend IntegerPart = toint(Latitude0)
| join kind=inner (Airport_Data) on $left.IntegerPart == $right.maxlatindicator
| where Latitude0 < minLatitude and Latitude0 < maxLatitude and Longitude0 > minLongitude and Longitude0  < maxLongitude
| summarize make_set(AirportName),  make_set(country),dcount(AirportName) by ActionType,RemoteIP,InitiatingProcessCommandLine,RemoteUrl, Country
```
