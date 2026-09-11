# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 2
- **Retention:** rolling 30 days
- **Last updated:** 2026-09-11
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
| mfs-0001 | Microsoft Advertising / Microsoft account | typosquat lookalike FQDN impersonating a Microsoft sign-in page (brand keywords + 'authentification' stuffed into a non-Microsoft host) | 2026-09-11 | OpenPhish (public feed) |
| mfs-0002 | Microsoft Entra ID / Azure AD | credential-phish on a compromised legitimate domain that replays the genuine AADSTS50058 error string to mimic a real Azure AD silent-auth redirect | 2026-09-11 | OpenPhish (public feed) |

### mfs-0001 — Microsoft Advertising / Microsoft account

```text
https://microsoft-advertising-authentification.sgn-1.com/signin/login.html
```

- **Domain:** `microsoft-advertising-authentification.sgn-1.com`
- **Technique:** typosquat lookalike FQDN impersonating a Microsoft sign-in page (brand keywords + 'authentification' stuffed into a non-Microsoft host)
- **Detection:** Alert on any non-microsoft.com host whose FQDN contains 'microsoft' together with 'auth'/'authentification'/'signin'; block *.sgn-1.com and flag /signin/login.html on unknown domains
- **Source:** OpenPhish (public feed) — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0002 — Microsoft Entra ID / Azure AD

```text
https://emanuelabsoluciones.com/_/?error=login_required&error_description=AADSTS50058:+A+silent+sign+in+request+was+sent+but+no+user+is+signed+in.+The+cookies+used+to+represent+the+user's+session+were+not+sent+in+the+request+to+Azure+AD.+This+can+happen+if+the+user+is+using+Internet+Explorer+or+Edge
```

- **Domain:** `emanuelabsoluciones.com`
- **Technique:** credential-phish on a compromised legitimate domain that replays the genuine AADSTS50058 error string to mimic a real Azure AD silent-auth redirect
- **Detection:** Hunt proxy/email/URL logs for external (non-login.microsoftonline.com) hosts carrying 'AADSTS50058' or 'error_description=login_required' query strings; these params should only ever appear on login.microsoftonline.com
- **Source:** OpenPhish (public feed) — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-11

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["microsoft-advertising-authentification.sgn-1.com", "emanuelabsoluciones.com"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

