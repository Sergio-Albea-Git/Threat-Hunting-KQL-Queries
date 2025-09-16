**Sign-in Attempts Using Deprecated TLS Versions**

**Description:**  This query identifies Azure AD sign-ins that are using legacy TLS versions (below TLS 1.2). It highlights the accounts, devices, and applications involved, providing visibility into insecure protocol usage. Tracking these events helps detect weak encryption risks and enables proactive remediation to enforce modern, secure standards. 

```
AADSignInEventsBeta
| where ErrorCode == 0
| mv-apply d = parse_json(AuthenticationProcessingDetails) on (
    extend key = tostring(d.key), value = tostring(d.value)
    | summarize details = make_bag(pack(key, value))
)
| extend LegacyTLS = tostring(details['Legacy TLS (TLS 1.0, 1.1, 3DES)'])
| where tolower(LegacyTLS) == "true"
| summarize Sessions = count()  
    by AccountUpn, ApplicationId, UserAgent, Timestamp,ReportId
| order by Sessions desc 
```
