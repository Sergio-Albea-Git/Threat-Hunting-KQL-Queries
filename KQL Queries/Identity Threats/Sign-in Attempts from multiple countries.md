##Success sign-in from more than 3 countries in one day based on the Latitude and Longitude distance among them##

##Description:##A while ago, I was annoyed with some Defender XDR alerts related to "User Impossible travel". I had different false positives,
users who were using VPN, different devices, different countries on the same day (not a surprise if you live in central Europe)
and others. So, I decided to create a query to find cases where the user success logins during the same day are from countries 
that are really distant.
The query checks the Longitude and Latitude difference of the first 4 countries, if I have more than 4 countries I will also be
notified. Sorry if there is any error with the calculation, I was (and I am) very bad at math :P 

```
let substring = ",";
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where isnotempty(Country)
| project AccountUpn, Timestamp, ClientAppUsed, Country, Latitude, Longitude, ReportId, DeviceTrustType
| summarize ['Count of countries']=dcount(Country), ['List of countries']=make_set(Country), ['ListofLatitudes']=make_set(Latitude),
 ['ListofLongitudes']=make_set(Longitude) by AccountUpn, DeviceTrustType
 | where ['Count of countries'] >= 3
 // | where DeviceTrustType !contains "Azure AD registered"
| project splitted=split(ListofLatitudes, '"'),splitted1=split(ListofLongitudes, '"'), ['List of countries'], AccountUpn, ['Count of countries']
//split Latitude and transform it output (if you want to add more countries, add Lat(+1)= splitted[+2] From the last, example --> Lat5 = splitted[9] )
| mv-expand Lat1=splitted[1], Lat2=splitted[3], Lat3=splitted[5], Lat4= splitted[7]
| extend Lat1 =todouble(Lat1), Lat2 = todouble(Lat2), Lat3 = todouble(Lat3), Lat4 = todouble(Lat4)
| extend Lat1 = round(Lat1), Lat2 = round(Lat2), Lat3 = round(Lat3), Lat4 = round(Lat4)
//split Longitude and transform it output (if you want to add more countries, add Long(+1)= splitted[+2] From the last, example --> Long = splitted[9])
| mv-expand Long1=splitted1[1], Long2=splitted1[3], Long3=splitted1[5], Long4= splitted1[7]
| extend Long1 =todouble(Long1), Long2 = todouble(Long2), Long3= todouble(Long3), Long4 = todouble(Long4)
| extend Long1 = round(Long1), Long2 = round(Long2), Long3 = round(Long3), Long4 = round(Long4)
// susbstract operations
| serialize resta = Lat1 - Lat2, resta2 = Lat1 - Lat2, resta3 = Lat2 - Lat3, resta4 = Lat1 - Lat4
| serialize restal = Long1 - Long2, restal2 = Long1 - Long3, restal3 = Long2 - Long3
// Calculate the distance, add more than 15 or 20 to see more distant countries
| where (resta > 15 and resta2 > 15 and resta3> 20 and Lat1 != Lat2 and Lat1!= Lat2 and Lat2!= Lat3) or (resta < -20 and resta2 < -15 and resta3 < -15) or (restal > 20 and restal2 > 20 and restal3> 20 and Long1 != Long2 and Long1!= Long2 and Long2!= Long3) or (restal < -20 and restal2 < -20 and restal3 < -20) or (['Count of countries'] >4)
| project AccountUpn,['List of countries']
```
