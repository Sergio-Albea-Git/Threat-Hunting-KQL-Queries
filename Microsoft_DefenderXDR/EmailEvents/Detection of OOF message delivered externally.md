**Detection of OOF message delivered externally**

 The following query is oriented to increase awareness about the content of OOF auto-reply messages, which often contain sensitive information such as:

- The period during a user is out (a prime time to target their account)
- Secondary email addresses to contact during it absence
- Phone numbers

The query summarize OOF messages delivered externally and classified by type of extension domain which could helps to identify where the mentioned information is being shared:
```
EmailEvents
// add your automatic replies cases in your languages
| where Subject startswith "Automatic reply:"
| where DeliveryAction has "Delivered" and EmailDirection has "Outbound"
| extend Username = split(RecipientEmailAddress, "@")[0], Domain = tostring(split(RecipientEmailAddress, "@")[1])
| extend DomainParts = split(RecipientEmailAddress, ".")
| extend DomainExtensions = tostring(DomainParts[-1])
| summarize count() by DomainExtensions ,EmailDirection, DeliveryAction,DeliveryLocation, ThreatTypes
// if you want to have deeper information instead of a general view, you can use the next line and remove/comment the previous one
//| distinct SenderDisplayName, SenderMailFromDomain, SenderIPv4, RecipientEmailAddress,DomainExtensions,Domain,Subject, EmailDirection, DeliveryAction, DeliveryLocation, ThreatTypes
```
