**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts |

**Author:** Sergio Albea (05/11/2026)

---

**Hunting for Suspicious Client Secret Authentication Attempt𝘀**

**Description:**  This week, I'm sharing a new article inspired by a recent investigation published by Todyl about attackers abusing stolen application credentials to authenticate as legitimate applications in Microsoft Entra ID.
The interesting part? Attackers don't necessarily need to compromise a user account. A stolen client secret could be enough to access sensitive cloud resources, depending on the application's permissions.
As usual, rather than focusing on IP-based IOCs that attackers can easily rotate, I prefer looking for Indicators of Attack (IOAs). For this hunt, I'm focusing on two Entra ID authentication errors:

- AADSTS7000215 – Invalid client secret
- AADSTS7000222 – Expired client secret

```
let UserSignIns = EntraIdSignInEvents
| where Timestamp > ago(7d) | where ErrorCode in (7000215, 7000222)
| project Timestamp, SourceTable = "UserSignIns", Application, IPAddress, Country, ErrorCode;
let SpnSignIns = EntraIdSpnSignInEvents | where Timestamp > ago(7d) | where ErrorCode in (7000215, 7000222)
| project Timestamp, SourceTable = "ServicePrincipalSignIns", Application, IPAddress, Country, ErrorCode;
union UserSignIns, SpnSignIns
| extend ErrorDescription = case(ErrorCode == 7000215, "Invalid client secret", ErrorCode == 7000222, "Expired client secret", "Other")
```
