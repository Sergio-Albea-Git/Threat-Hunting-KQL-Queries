**Monitoring M.Teams activities such as shared URLs, OneToOne chats and Domains participating into meetings**

New day, new KQL query, this time oriented to identify Microsoft Teams activities such as:

- URL's shared into Teams Chat or Channels (Case 1)
- Domains participating into Teams meetings or channels (Case 2)
- One to One Chats which can be related to scam (bad actors contact you by Teams externally to request info or saying that they are part of support team, reported case in a recent event 🎤 ) (Case 3)
- Identify non-compliance or non-allowed Teams Channels/Groups names

```
CloudAppEvents
| where Application has "Microsoft Teams"
| extend Geo_IP = tostring(geo_info_from_ip_address(IPAddress).country)
| extend ChatName = todynamic(RawEventData).ChatName
| extend TeamName = todynamic(RawEventData).TeamName
| extend ChannelName = todynamic(RawEventData).ChannelName
| extend Operation = todynamic(RawEventData).Operation
| extend CommunicationType = todynamic(RawEventData).CommunicationType
| extend MessageURLs = tostring(todynamic(RawEventData).MessageURLs)
| mv-expand  ParticipantsInfo =(RawEventData).ParticipantInfo
| extend HasGuestUsers = (ParticipantsInfo).HasGuestUsers
| extend HasForeignTenantUsers = (ParticipantsInfo).HasForeignTenantUsers
| extend ParticipatingDomains = (ParticipantsInfo).ParticipatingDomains
// Case 1 Review URL's sent by Teams | where isnotempty (MessageURLs) and Operation has "MessageCreatedHasLink"
// Case 2 Review Domains participating into meetings | where ParticipatingDomains contains "."
// Case 3 Review One to One communications| where CommunicationType has "OneOnOne" and Operation has "MessageSent"
| project ActionType, AccountDisplayName, IPAddress,Geo_IP, CountryCode,ChatName,Operation,TeamName,ChannelName, MessageURLs,HasForeignTenantUsers,HasGuestUsers,ParticipatingDomains, CommunicationType
```
