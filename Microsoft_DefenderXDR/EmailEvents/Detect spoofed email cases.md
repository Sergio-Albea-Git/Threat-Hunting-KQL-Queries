**Detection of spoofed Emails**

It has been a long journey to create a query that shows a high percentage of true positives regarding spoofed emails, but finally, I am proud of the results achieved!
Basically, I check emails received where the DisplayName matches with EntraID DisplayName Accounts, and then I apply multiple filters and conditions to obtain the most accurate true positive results.
```
EmailEvents
| join kind=inner (IdentityInfo) on $left.SenderDisplayName == $right.AccountDisplayName
// Filter by emails detected as Threat, delivered into Inbox-Folder and non-sent by owned Email Domains
| where isnotempty(ThreatTypes) and DeliveryLocation contains "Inbox" and SenderMailFromDomain !in ("domain1.com","domain2.com")
// excluding OOF mails, auto-replies or blank DisplayNames also helps to reduce false positives
| where Subject !startswith "Automatic reply" and isnotempty(SenderDisplayName)
// The following lines are used to see if the recipient contains the surname of the sender which could means that the user is forwarding emails to it personal email. If due to some DLP Policies it should not be allowed, you can remove these lines
| extend DNsplit=split(SenderDisplayName, " ")
| extend name = tostring(DNsplit[0])
| extend surname = tostring(DNsplit[1])
| extend surname = tolower(surname)
| where RecipientEmailAddress !contains surname
// if you have some internal services such as Sharepoint, you can add your internal Network to be excluded and detect spoofing cases sent by another Sharepoint services 
| where SenderFromDomain !contains "sharepoint" and SenderIPv4 !startswith "20.117.7"
| project SenderDisplayName, surname,AccountDisplayName, SenderMailFromAddress, RecipientEmailAddress,SenderFromAddress, Subject, SenderIPv4


```
