**Communication at risk due to the encryption algorithms (Ciphers) in use**

**Description**: This query is using the DeviceNetworkEvents table to filter  by connections where there are encryption algorithms used.
Then, I take a list of the encryption algorithms database from the well-known site iana.org which is an entity that monitors the global allocation of IP addresses, autonomous systems, DNS domain name root servers and other Internet Protocol resources.
Finally, It list cases where there are multiple connections established using non-recommended or non-valid datagram transport layer security (DTLS), which could mean that our users are not protected against eavesdropping, tampering or message forgery. 

```
let CVE = externaldata(Value:string,Description:string,DTLSOK:string,Recommended:string,Reference:string)
[@"https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"] with (format="csv");
DeviceNetworkEvents
| extend cipher = parse_json(AdditionalFields).cipher
| extend cipher = tostring(cipher)
| where isnotempty(cipher)
| extend RemoteIPCountry = geo_info_from_ip_address(RemoteIP).country
| extend RemoteIPCountry = tostring(RemoteIPCountry)
| join kind=inner (CVE) on $left.cipher == $right.Description
// just listing non-recommended TLS versions or communications where the Datagram Transport Layer Security (DTLS) is not OK
| where DTLSOK has "N" or Recommended has "N"
// creating a new column to have RFC URL Reference
| extend RFCLink = tolower(Reference)
| extend RFCLink = substring(RFCLink, 1, strlen(RFCLink) - 2)
| extend RFCLink = strcat("rfc-editor.org/rfc/",RFCLink,".html")
| extend RFCLink = tostring(RFCLink)
// sorting by Totalconnections to find out if there are any repetitive connections using low encryption
 | summarize Totalconnections=count() by RemoteIP, RemoteIPCountry, TenantId,DeviceName, LocalIP,ActionType, RemotePort, Protocol, cipher, Value,Description, DTLSOK, Recommended, Reference, RFCLink
| order by Totalconnections
```
