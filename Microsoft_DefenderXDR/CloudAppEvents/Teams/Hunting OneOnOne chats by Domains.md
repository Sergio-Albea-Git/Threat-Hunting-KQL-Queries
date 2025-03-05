**Hunting OneOnOne chats by Domains**

The following KQL query helps detect domains interacting with OneOnOne Teams Chats in your tenant, and allows to whitelist trusted or known domains while flagging suspicious ones.

```
CloudAppEvents
| where Application has "Microsoft Teams" and isnotempty(IPAddress)  
| extend Geo_IP = tostring(geo_info_from_ip_address(IPAddress).country)
| extend ChatName = todynamic(RawEventData).ChatName
| extend TeamName = todynamic(RawEventData).TeamName
| extend ChannelName = todynamic(RawEventData).ChannelName
| extend Operation = todynamic(RawEventData).Operation
| extend CommunicationType = todynamic(RawEventData).CommunicationType
| where  Operation has "ChatCreated" and CommunicationType has "OneOnOne"
| mv-expand  ParticipantsInfo = (todynamic(parse_json(RawEventData).ParticipantInfo))
|  mv-expand  ParticipatingDomains =  (ParticipantsInfo).ParticipatingDomains
|  mv-expand  ParticipatingSIPDomains =  (ParticipantsInfo).ParticipatingSIPDomains
|  mv-expand  ParticipatingSIPDomains =  (ParticipatingSIPDomains).DomainName
| where  Operation has "ChatCreated" and CommunicationType has "OneOnOne"
| where (ParticipatingDomains!="" or  ParticipatingSIPDomains!="") and (ParticipatingDomains !in ("microsoft.com") or ParticipatingSIPDomains !in ("microsoft.com"))
| project  AccountDisplayName,ChatCreatedFrom= IPAddress,ChannelName,ChatName, TeamName,Geo_IP, CountryCode,Operation,ParticipatingSIPDomains,ParticipatingDomains, ISP
```
