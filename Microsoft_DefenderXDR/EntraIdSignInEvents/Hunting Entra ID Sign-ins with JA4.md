**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts |

**Author:** Sergio Albea (13/09/2026)

---

**Hunting Entra ID Sign-ins with JA4**

**Description:**  The EntraIdSignInEvents table exposes the JA4 fingerprint in the GatewayJA4 field. But looking at the complete fingerprint alone does not tell us much. The interesting part starts when we break it down. With a simple KQL query, we can separate the TLS version, SNI, number of cipher suites, extensions and ALPN, together with the cipher and extension hashes. Then we can see how many sign-ins, users, IPs and countries are behind each JA4.
The idea is simple: understand what is normal first, then look for what is different.

```
//Sergio Albea 13-09-2026
EntraIdSignInEvents | where Timestamp > ago(1d) and isnotempty(GatewayJA4)
| extend JA4Parts = split(GatewayJA4, "_")
| extend JA4_A = tostring(JA4Parts[0]), JA4_CipherHash = tostring(JA4Parts[1]), JA4_ExtensionHash = tostring(JA4Parts[2])
| extend Transport = substring(JA4_A, 0, 1), TLSVersion = substring(JA4_A, 1, 2), SNI = substring(JA4_A, 3, 1), CipherCount = toint(substring(JA4_A, 4, 2)), ExtensionCount = toint(substring(JA4_A, 6, 2)),
    ALPN = substring(JA4_A, 8, 2)
| summarize SignIns = count(), Users = dcount(AccountUpn), IPs = dcount(IPAddress), Countries = dcount(Country)
    by GatewayJA4, Transport, TLSVersion, SNI, CipherCount, ExtensionCount, ALPN, JA4_CipherHash, JA4_ExtensionHash
```
