**Detecting connections affected by the Blocking Legacy Authentication enforcement expected by July 2025**

Beginning in July, access to services like SharePoint, OneDrive, and Office files using outdated authentication methods—such as RPS and FPRPC—will be blocked, with full implementation expected by August. This change is part of Microsoft’s broader strategy under the Secure Future Initiative (SFI), which promotes a “Secure by Default” approach to help organizations maintain a strong baseline of protection.
The following KQL queries will help you to detect remaining connections using the legacy authentication methods


```
AADSignInEventsBeta
| where ErrorCode == "0"
| where Timestamp > ago(7d)
| where ClientAppUsed in ("Exchange ActiveSync", "Exchange Web Services", "AutoDiscover", "Unknown", "POP3", "IMAP4", "Other clients", "Authenticated SMTP", "MAPI Over HTTP", "Offline Address Book")
 or UserAgent in("BAV2ROPC", "CBAinPROD", "CBAinTAR", "MSRPC")
| summarize by AccountDisplayName, IPAddress, AccountUpn, ClientAppUsed, UserAgent
```
