**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| T1573 |   Encrypted Channel |

**Author:** Sergio Albea (13/09/2026)

---

**Investigate JA4 and JA4s connections on DeviceNetworkEvents**

**Description:** In DeviceNetworkEvents, we can find both JA4 and JA4S inside AdditionalFields for some TLS connections. This is interesting because we can look at both sides of the same TLS communication. We can compare clients, servers and JA4/JA4S combinations, and look for patterns or connections that behave differently from what we normally see. The following KQL extracts and decodes both fingerprints from the same network event.

```
//Sergio Albea 13-09-2026
DeviceNetworkEvents
//| where ActionType == "SslConnectionInspected"
| extend geo_ip = tostring(geo_info_from_ip_address(RemoteIP).country)
| where isnotempty(geo_ip)
| extend AF = parse_json(AdditionalFields)
| extend JA4 = tostring(AF.ja4), JA4S = tostring(AF.ja4s)
| where isnotempty(JA4) or isnotempty(JA4S)
// JA4 - Client
| extend JA4_Parts = split(JA4, "_")
| extend JA4_A = tostring(JA4_Parts[0]), JA4_B = tostring(JA4_Parts[1]), JA4_C = tostring(JA4_Parts[2])
| extend JA4_Transport = substring(JA4_A, 0, 1), JA4_TLS_Version = substring(JA4_A, 1, 2), JA4_SNI = substring(JA4_A, 3, 1), JA4_Cipher_Count = toint(substring(JA4_A, 4, 2)), JA4_Extension_Count = toint(substring(JA4_A, 6, 2)), JA4_ALPN = substring(JA4_A, 8, 2)
| extend JA4_Transport = case(JA4_Transport == "t", "TCP", JA4_Transport == "q", "QUIC", JA4_Transport), JA4_TLS_Version = case(JA4_TLS_Version == "13", "TLS 1.3", JA4_TLS_Version == "12", "TLS 1.2", JA4_TLS_Version == "11", "TLS 1.1", JA4_TLS_Version == "10", "TLS 1.0", JA4_TLS_Version), JA4_SNI = case(JA4_SNI == "d", "SNI Present", JA4_SNI == "i", "SNI Not Present", "Unknown"), JA4_ALPN = case(JA4_ALPN == "h2", "HTTP/2", JA4_ALPN == "h1", "HTTP/1.x", JA4_ALPN == "00", "No ALPN", JA4_ALPN)
// JA4S - Server
| extend JA4S_Parts = split(JA4S, "_")
| extend JA4S_A = tostring(JA4S_Parts[0]), JA4S_B = tostring(JA4S_Parts[1]), JA4S_C = tostring(JA4S_Parts[2])
| extend JA4S_Transport = substring(JA4S_A, 0, 1), JA4S_TLS_Version = substring(JA4S_A, 1, 2), JA4S_Extension_Count = toint(substring(JA4S_A, 3, 2)), JA4S_ALPN = substring(JA4S_A, 5, 2)
| extend JA4S_Transport = case(JA4S_Transport == "t", "TCP", JA4S_Transport == "q", "QUIC", JA4S_Transport), JA4S_TLS_Version = case(JA4S_TLS_Version == "13", "TLS 1.3", JA4S_TLS_Version == "12", "TLS 1.2", JA4S_TLS_Version == "11", "TLS 1.1", JA4S_TLS_Version == "10", "TLS 1.0", JA4S_TLS_Version), JA4S_ALPN = case(JA4S_ALPN == "h2", "HTTP/2", JA4S_ALPN == "h1", "HTTP/1.x", JA4S_ALPN == "00", "No ALPN", JA4S_ALPN)
| project Timestamp, AdditionalFields,DeviceName, ActionType, RemoteUrl, RemoteIP, geo_ip, JA4, JA4_Transport, JA4_TLS_Version, JA4_SNI, JA4_Cipher_Count, JA4_Extension_Count, JA4_ALPN, JA4_Cipher_Hash=JA4_B, JA4_Extension_Hash=JA4_C, JA4S, JA4S_Transport, JA4S_TLS_Version, JA4S_Extension_Count, JA4S_ALPN, JA4S_Selected_Cipher=JA4S_B, JA4S_Extension_Hash=JA4S_C
| order by Timestamp desc
```
