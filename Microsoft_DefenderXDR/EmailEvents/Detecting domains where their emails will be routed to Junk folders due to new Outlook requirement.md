**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment |

**Author:** Sergio Albea (05/06/2026)

---

**Detecting domains where their emails will be routed to Junk folders due to new Outlook requirement**

Microsoft has reported that After May 5th, 2025, Outlook will begin routing messages from high volume non‐compliant domains to the Junk folder, giving senders an opportunity to address any outstanding issues.
𝐍𝐎𝐓𝐄: 𝐭𝐡𝐚𝐭 𝐢𝐧 𝐭𝐡𝐞 𝐟𝐮𝐭𝐮𝐫𝐞 (𝐝𝐚𝐭𝐞 𝐭𝐨 𝐛𝐞 𝐚𝐧𝐧𝐨𝐮𝐧𝐜𝐞𝐝), 𝐧𝐨𝐧-𝐜𝐨𝐦𝐩𝐥𝐢𝐚𝐧𝐭 𝐦𝐞𝐬𝐬𝐚𝐠𝐞𝐬 𝐰𝐢𝐥𝐥 𝐛𝐞 𝐫𝐞𝐣𝐞𝐜𝐭𝐞𝐝 𝐭𝐨 𝐟𝐮𝐫𝐭𝐡𝐞𝐫 𝐩𝐫𝐨𝐭𝐞𝐜𝐭 𝐮𝐬𝐞𝐫𝐬. 

For domains sending over 5,000 emails per day, Outlook will soon require compliance with SPF, DKIM, DMARC. Non‐compliant messages will first be routed to Junk. If issues remain unresolved, they may eventually be rejected. Senders will soon start requiring compliance with the following requirements: 

- SPF (Sender Policy Framework)
Must Pass for the sending domain.
Your domain's DNS record should accurately list authorized IP addresses/hosts.
- DKIM (DomainKeys Identified Mail)
Must Pass to validate email integrity and authenticity.
- DMARC (Domain-based Message Authentication, Reporting, and Conformance)
At least p=none and align with either SPF or DKIM (preferably both).

```
EmailEvents
| where Timestamp > ago(1d)
| extend SPF = tostring(parse_json(AuthenticationDetails).SPF)
| extend DMARC = tostring(parse_json(AuthenticationDetails).DMARC)
| extend DKIM = tostring(parse_json(AuthenticationDetails).DKIM)
| where SPF !has "pass" or DMARC !has "pass" or DKIM !has "pass"
| summarize Total_Emails=count() by InternetMessageId, SenderFromDomain, SPF, DMARC, DKIM
| where Total_Emails > 4000
| order by Total_Emails
```
