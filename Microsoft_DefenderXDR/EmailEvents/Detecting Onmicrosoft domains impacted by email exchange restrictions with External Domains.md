**Detecting Onmicrosoft domains impacted by email exchange restrictions with External Domains(June 2026)**

 Microsoft has announced new restrictions on email sending for organizations that use the default onmicrosoft domains.
A throttling system will be enforced, limiting external email delivery to a maximum of 100 recipients per organization every 24 hours. To summarize:

1. Microsoft limits onmicrosoft.com domains to 100 external emails daily.
2. Targets cybercriminals exploiting new tenants, protecting shared domain reputation.
3. Organizations must purchase custom domains, rollout phases through June 2026.

The following KQL Query shows the number of distinct external domains where your onmicosoft.com domain, has been sending emails during a day. Could be that you don't detect 100 domains x day but in any case, I would recommend to start to purchase / configure your own domains instead of use the mentioned one.

```
EmailEvents
| where SenderFromDomain endswith "onmicrosoft.com"
| extend Date_F = format_datetime(Timestamp, "yyyy-MM-dd")
| summarize make_set(RecipientDomain), Total_External_Domains=dcount(RecipientDomain) by SenderFromDomain,Date_F
| order by Total_External_Domains

```
