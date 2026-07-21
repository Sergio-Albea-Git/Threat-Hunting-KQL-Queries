**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1598.003 | Phishing for Information: Spearphishing Link |

**Author:** Sergio Albea (14/05/2025)

---

**User Information collected externally when a URL is clicked**

Email campaigns using postmarkapp.com allows to collect information about the users that click on a URL formatted by this system. They can contains valid domains in the URL but at the begging , it will contains a text such as track.pstmrk.it which will back private information to the sender:
'When Link Tracking has been enabled, links in your messages will be replaced with new links that route through Postmark servers. When an email recipient clicks on a tracked link, the URL is opened in their default browser. 𝐓𝐡𝐞 𝐛𝐫𝐨𝐰𝐬𝐞𝐫 𝐰𝐢𝐥𝐥 𝐫𝐞𝐪𝐮𝐞𝐬𝐭 𝐭𝐡𝐞 𝐔𝐑𝐋 𝐟𝐫𝐨𝐦 𝐨𝐧𝐞 𝐨𝐟 𝐨𝐮𝐫 𝐏𝐨𝐬𝐭𝐦𝐚𝐫𝐤 𝐬𝐞𝐫𝐯𝐞𝐫𝐬, 𝐚𝐭 𝐰𝐡𝐢𝐜𝐡 𝐩𝐨𝐢𝐧𝐭 𝐰𝐞 𝐫𝐞𝐜𝐨𝐫𝐝 𝐢𝐧𝐟𝐨𝐫𝐦𝐚𝐭𝐢𝐨𝐧 𝐚𝐛𝐨𝐮𝐭 𝐭𝐡𝐞 𝐮𝐬𝐞𝐫'𝐬 𝐥𝐨𝐜𝐚𝐭𝐢𝐨𝐧, 𝐰𝐡𝐚𝐭 𝐛𝐫𝐨𝐰𝐬𝐞𝐫 𝐭𝐡𝐞𝐲 𝐚𝐫𝐞 𝐮𝐬𝐢𝐧𝐠, 𝐚𝐧𝐝 𝐢𝐧 𝐰𝐡𝐢𝐜𝐡 𝐩𝐚𝐫𝐭 𝐨𝐟 𝐭𝐡𝐞 𝐞𝐦𝐚𝐢𝐥 𝐭𝐡𝐞 𝐥𝐢𝐧𝐤 𝐰𝐚𝐬 𝐜𝐥𝐢𝐜𝐤𝐞𝐝 (𝐇𝐓𝐌𝐋 𝐨𝐫 𝐓𝐞𝐱𝐭).'
 Malicious senders collecting geolocation data and browser details could be laying the groundwork for further malicious activity.
```
UrlClickEvents
| where Url contains ".pstmrk.it"
| join kind=inner (EmailEvents) on $left.NetworkMessageId == $right.NetworkMessageId
| where DeliveryLocation has "Inbox"
```
