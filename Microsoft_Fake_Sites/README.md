# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 18
- **Retention:** rolling 30 days
- **Last updated:** 2026-09-12
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
| mfs-0001 | Microsoft Advertising / Microsoft account | typosquat lookalike FQDN impersonating a Microsoft sign-in page (brand keywords + 'authentification' stuffed into a non-Microsoft host) | 2026-09-11 | OpenPhish (public feed) |
| mfs-0002 | Microsoft Entra ID / Azure AD | credential-phish on a compromised legitimate domain that replays the genuine AADSTS50058 error string to mimic a real Azure AD silent-auth redirect | 2026-09-11 | OpenPhish (public feed) |
| mfs-0003 | Microsoft 365 | typosquat credential-harvester abusing free Vercel hosting (brand name in *.vercel.app subdomain) | 2026-09-06 | TweetFeed.live (X researcher @skocherhan) |
| mfs-0004 | Microsoft 365 | typosquat domain ('notifcation' missing an 'i') hosting PHP credential-harvest kit with per-victim token path | 2026-09-07 | TweetFeed.live (@phishunt_io) |
| mfs-0005 | Microsoft 365 (OneDrive) | AiTM PhaaS ('EvilTokens'/ARTOKEN affiliate panel) hosted on Cloudflare Workers, OneDrive-themed doc lure | 2026-09-12 | Cisco Talos IOCs |
| mfs-0006 | Microsoft 365 | AiTM credential/token harvester (Cloudflare Workers docviewer stage) in EvilTokens affiliate kit | 2026-09-12 | Cisco Talos IOCs |
| mfs-0007 | Microsoft 365 | AiTM phishing C2/panel domain (pamconj.com) for EvilTokens Microsoft 365 credential theft | 2026-09-12 | Cisco Talos IOCs |
| mfs-0008 | Microsoft 365 | Typosquat ('0nline') credential-harvest page abusing Google App Engine (appspot.com) hosting | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0009 | Microsoft Outlook | Outlook sign-in clone on Google App Engine, brand keywords stuffed into subdomain | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0010 | Office 365 / Outlook | Office 365 sign-in phishing on App Engine (off365 typo lure) | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0011 | Microsoft Live / Office 365 | Free-hosting (wze.io) phishing with fake 'live.com/microsoftoffice365' path masquerade | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0012 | Office 365 | Compromised legitimate site hosting voicemail-themed Office 365 credential page | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0013 | Office 365 | Document-share lure ('newprojectdocument') on App Engine leading to Office 365 login clone | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0014 | Office 365 / OneDrive | OneDrive/LinkedIn document lure on App Engine, off365.html credential page | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0015 | Office 365 | App Engine auto-generated hostname serving off365.html credential-harvest page | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0016 | Office 365 | Voicemail ('voicemail365') themed Office 365 phishing on Google App Engine | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0017 | Office 365 | Fake 'Office 365 portal verification' page on App Engine | 2026-09-12 | SecurityTechie IOC repo |
| mfs-0018 | Office 365 | Free-TLD (.ga) random-string domain hosting 'Office-BG' login.php credential harvester | 2026-09-12 | SecurityTechie IOC repo |

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

### mfs-0003 — Microsoft 365

```text
http://microsoft-alpha.vercel.app
```

- **Domain:** `microsoft-alpha.vercel.app`
- **Technique:** typosquat credential-harvester abusing free Vercel hosting (brand name in *.vercel.app subdomain)
- **Detection:** Alert on Microsoft/Entra sign-in pages served from *.vercel.app; hunt proxy/DNS logs for vercel.app hostnames containing 'microsoft'
- **Source:** TweetFeed.live (X researcher @skocherhan) — https://x.com/skocherhan/status/2096614707666755746
- **Status:** active
- **First seen:** 2026-09-06

### mfs-0004 — Microsoft 365

```text
http://watco.microsoft-notifcation.com/wa4d1737192/78b65c00e4993df97452c88c/index.php?id=60f29657ebf9c47f483976bd43ae
```

- **Domain:** `watco.microsoft-notifcation.com`
- **Technique:** typosquat domain ('notifcation' missing an 'i') hosting PHP credential-harvest kit with per-victim token path
- **Detection:** Block parent domain microsoft-notifcation.com; hunt for GET/POST to /index.php?id=<long-hex> under microsoft-lookalike hosts and newly-registered 'microsoft-*notif*' domains
- **Source:** TweetFeed.live (@phishunt_io) — https://x.com/phishunt_io/status/2096931771958862091
- **Status:** active
- **First seen:** 2026-09-07

### mfs-0005 — Microsoft 365 (OneDrive)

```text
https://50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document.workers.dev
```

- **Domain:** `50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document.workers.dev`
- **Technique:** AiTM PhaaS ('EvilTokens'/ARTOKEN affiliate panel) hosted on Cloudflare Workers, OneDrive-themed doc lure
- **Detection:** Alert on *.workers.dev hosts with 'onedrive'/'docviewer' labels + long random UUID-style subdomains proxying login.microsoftonline.com
- **Source:** Cisco Talos IOCs — https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365.json
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0006 — Microsoft 365

```text
https://aquaclaude-09494-9099403-docviewer.clear90489058903-document.workers.dev
```

- **Domain:** `aquaclaude-09494-9099403-docviewer.clear90489058903-document.workers.dev`
- **Technique:** AiTM credential/token harvester (Cloudflare Workers docviewer stage) in EvilTokens affiliate kit
- **Detection:** Hunt DNS/proxy logs for the shared parent 'clear90489058903-document.workers.dev' and its docviewer subdomains
- **Source:** Cisco Talos IOCs — https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365.json
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0007 — Microsoft 365

```text
https://spx.pamconj.com
```

- **Domain:** `spx.pamconj.com`
- **Technique:** AiTM phishing C2/panel domain (pamconj.com) for EvilTokens Microsoft 365 credential theft
- **Detection:** Block pamconj.com and subdomains (spx., dashboard-bl.); flag first-seen low-reputation domain resolving to 172.67.214.35
- **Source:** Cisco Talos IOCs — https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365.json
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0008 — Microsoft 365

```text
https://login-microsoft-0nline.ts.r.appspot.com/index.php
```

- **Domain:** `login-microsoft-0nline.ts.r.appspot.com`
- **Technique:** Typosquat ('0nline') credential-harvest page abusing Google App Engine (appspot.com) hosting
- **Detection:** Alert on *.r.appspot.com hosts whose subdomain contains 'microsoft'/'login'/'0nline' serving index.php login forms
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0009 — Microsoft Outlook

```text
https://login-microsoft-outlook.el.r.appspot.com/index.html
```

- **Domain:** `login-microsoft-outlook.el.r.appspot.com`
- **Technique:** Outlook sign-in clone on Google App Engine, brand keywords stuffed into subdomain
- **Detection:** Proxy rule: *.r.appspot.com with 'outlook'/'microsoft' in host label and static index.html login page
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0010 — Office 365 / Outlook

```text
https://tlook-off365-signin.el.r.appspot.com/
```

- **Domain:** `tlook-off365-signin.el.r.appspot.com`
- **Technique:** Office 365 sign-in phishing on App Engine (off365 typo lure)
- **Detection:** Regex host match /(off?365|tlook|signin)/ on *.r.appspot.com
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0011 — Microsoft Live / Office 365

```text
https://xmaksvwq.wze.io/live.com/microsoftoffice365/
```

- **Domain:** `xmaksvwq.wze.io`
- **Technique:** Free-hosting (wze.io) phishing with fake 'live.com/microsoftoffice365' path masquerade
- **Detection:** Flag *.wze.io URLs containing 'live.com' or 'microsoftoffice365' path segments
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0012 — Office 365

```text
https://noithatviet24h.vn/voice/office/index.php
```

- **Domain:** `noithatviet24h.vn`
- **Technique:** Compromised legitimate site hosting voicemail-themed Office 365 credential page
- **Detection:** Hunt for /voice/office/ or /office/index.php paths on unrelated (non-Microsoft) domains
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0013 — Office 365

```text
http://newprojectdocument.uc.r.appspot.com/accessed11/index.html
```

- **Domain:** `newprojectdocument.uc.r.appspot.com`
- **Technique:** Document-share lure ('newprojectdocument') on App Engine leading to Office 365 login clone
- **Detection:** Block *.r.appspot.com hosts with document/onedrive lure labels serving /accessed*/index.html
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0014 — Office 365 / OneDrive

```text
http://onedrivelinkedindocument.oa.r.appspot.com/off365.html
```

- **Domain:** `onedrivelinkedindocument.oa.r.appspot.com`
- **Technique:** OneDrive/LinkedIn document lure on App Engine, off365.html credential page
- **Detection:** Alert on 'off365.html' filename and 'onedrive'/'linkedin' subdomain labels on appspot.com
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0015 — Office 365

```text
http://spherical-door-277805.uc.r.appspot.com/off365.html
```

- **Domain:** `spherical-door-277805.uc.r.appspot.com`
- **Technique:** App Engine auto-generated hostname serving off365.html credential-harvest page
- **Detection:** Same-kit indicator: 'off365.html' on random *.r.appspot.com project hosts
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0016 — Office 365

```text
http://voicemail365.nn.r.appspot.com/index.html
```

- **Domain:** `voicemail365.nn.r.appspot.com`
- **Technique:** Voicemail ('voicemail365') themed Office 365 phishing on Google App Engine
- **Detection:** Flag 'voicemail'/'365' subdomain labels on *.r.appspot.com with login index.html
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0017 — Office 365

```text
http://office365-portal-verify.el.r.appspot.com/
```

- **Domain:** `office365-portal-verify.el.r.appspot.com`
- **Technique:** Fake 'Office 365 portal verification' page on App Engine
- **Detection:** Host regex /office365.*(portal|verify|signin)/ on appspot.com
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0018 — Office 365

```text
https://loginblxxslingfbvfgh600ohjm.ga/veakermt/Office-BG/login.php
```

- **Domain:** `loginblxxslingfbvfgh600ohjm.ga`
- **Technique:** Free-TLD (.ga) random-string domain hosting 'Office-BG' login.php credential harvester
- **Detection:** Block .ga/.tk/.ml domains with high-entropy hostnames and /Office*/login.php paths
- **Source:** SecurityTechie IOC repo — https://github.com/SecurityTechie/Indicators-of-Compromise-IOC-/blob/master/Phishing%20Domains
- **Status:** active
- **First seen:** 2026-09-12

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["microsoft-advertising-authentification.sgn-1.com", "emanuelabsoluciones.com", "microsoft-alpha.vercel.app", "watco.microsoft-notifcation.com", "50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document.workers.dev", "aquaclaude-09494-9099403-docviewer.clear90489058903-document.workers.dev", "spx.pamconj.com", "login-microsoft-0nline.ts.r.appspot.com", "login-microsoft-outlook.el.r.appspot.com", "tlook-off365-signin.el.r.appspot.com", "xmaksvwq.wze.io", "noithatviet24h.vn", "newprojectdocument.uc.r.appspot.com", "onedrivelinkedindocument.oa.r.appspot.com", "spherical-door-277805.uc.r.appspot.com", "voicemail365.nn.r.appspot.com", "office365-portal-verify.el.r.appspot.com", "loginblxxslingfbvfgh600ohjm.ga"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

