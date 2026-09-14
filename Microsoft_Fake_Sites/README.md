# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 78
- **Retention:** rolling 30 days
- **Last updated:** 2026-09-14
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
| mfs-0019 | Microsoft 365 | typosquat credential-harvest domain ("microsoft-ssl" impersonation) | 2026-09-04 | OpenPhish (via phishunt.io) |
| mfs-0020 | Microsoft Outlook / Office 365 | typosquat login page on free subdomain host (yzz.me) | 2026-09-09 | OpenPhish (via phishunt.io) |
| mfs-0021 | Microsoft OneDrive | compromised legit site hosting obfuscated HTML credential page | 2026-09-02 | OpenPhish (via phishunt.io) |
| mfs-0022 | Microsoft 365 | AiTM/MFA-relay lure on 'support'-themed lookalike domain | 2026-08-30 | OpenPhish (via phishunt.io) |
| mfs-0024 | Microsoft | compromised Brazilian law-firm site hosting fake 'microsoft-store' page | 2026-09-02 | OpenPhish (via phishunt.io) |
| mfs-0025 | Microsoft Word / Office 365 | abuse of Blogspot free hosting for brand-impersonation landing page | 2026-09-01 | OpenPhish (via phishunt.io) |
| mfs-0026 | Microsoft 365 | abuse of Vercel hosting for Microsoft-branded phishing app | 2026-08-28 | OpenPhish (via phishunt.io) |
| mfs-0027 | Microsoft Outlook | typosquat credential-harvest landing page ('proteccion-outlook2026') | 2026-09-13 | OpenPhish (via phishunt.io) |
| mfs-0028 | Microsoft 365 | AiTM (Knight Office kit) proxying M365/SharePoint/Teams login for token theft | 2026-09-02 | Huntress |
| mfs-0029 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for session-token theft | 2026-09-02 | Huntress |
| mfs-0030 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0031 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0032 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0033 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0034 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0035 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0036 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0037 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0038 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0039 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0040 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0041 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0042 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0043 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0044 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0045 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0046 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0047 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0048 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0049 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0050 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0051 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0052 | Microsoft 365 | AiTM (Knight Office kit) proxying M365 login for token theft | 2026-09-02 | Huntress |
| mfs-0056 | Microsoft Entra ID | IT-help-desk vishing + passkey-enrollment AiTM (O-UNC-066 'Pink') | 2026-09-11 | The Hacker News |
| mfs-0057 | Microsoft Entra ID | Passkey-themed AiTM phishing mimicking Microsoft sign-in via SMS lures | 2026-09-11 | The Hacker News |
| mfs-0058 | Microsoft 365 | Passkey-enrollment phishing directing users to counterfeit Microsoft sign-in | 2026-09-11 | The Hacker News |
| mfs-0059 | Microsoft Entra ID | Fake passkey-setup portal harvesting Microsoft creds/session | 2026-09-11 | The Hacker News |
| mfs-0060 | Microsoft 365 | Counterfeit Microsoft portal-setup page in passkey/SSO vishing campaign | 2026-09-11 | The Hacker News |
| mfs-0068 | Microsoft OneDrive | fake OneDrive document portal harvesting M365 creds (Google/Cloudflare infra abuse) | 2026-09-01 | GBHackers |
| mfs-0069 | Microsoft 365 | M365 credential harvester behind interstitial gate (.vu abuse) | 2026-09-01 | GBHackers |
| mfs-0070 | Microsoft Teams / 365 | compromised WordPress site hiding M365/Teams phishing kit in legit dirs | 2026-09-01 | GBHackers |
| mfs-0071 | Microsoft Teams / 365 | compromised-site phishing kit in nested admin path | 2026-09-01 | GBHackers |
| mfs-0072 | Microsoft 365 / Outlook | voicemail-lure phishing kit hidden in /config/.bin/ backend dir | 2026-09-01 | GBHackers |
| mfs-0073 | Microsoft 365 | AiTM passkey/SSO-themed vishing lure (help-desk impersonation, victim-specific subdomains capture creds + MFA tokens) | 2026-09-08 | Arctic Wolf (PREY-0058 / Cordial Spider) |
| mfs-0074 | Microsoft 365 | AiTM passkey/MFA re-enrollment lure via IT help-desk vishing | 2026-09-08 | Arctic Wolf (PREY-0058 / Cordial Spider) |
| mfs-0075 | Microsoft 365 | AiTM SSO-setup lure (Microsoft 365 / Okta-Duo credential + MFA capture) | 2026-09-08 | Arctic Wolf (PREY-0058 / Cordial Spider) |
| mfs-0076 | Microsoft 365 | AiTM 'oskey/passkey setup' lure delivered via voice phishing | 2026-09-08 | Arctic Wolf (PREY-0058 / Cordial Spider) |
| mfs-0077 | Microsoft 365 | AiTM passkey+MFA themed credential/token harvester | 2026-09-08 | Arctic Wolf (PREY-0058 / Cordial Spider) |
| mfs-0078 | Microsoft 365 | AiTM SSO-integration lure with victim-company subdomains (companyname.integratedsso.com) | 2026-09-09 | Microsoft / Arctic Wolf (PREY-0058) |
| mfs-0079 | Microsoft 365 / Okta | AiTM SSO-session lure impersonating Microsoft/Okta sign-in during help-desk vishing | 2026-09-09 | Microsoft (passkey-themed M365 phishing research) |
| mfs-0080 | Microsoft 365 | AiTM 'key sync/passkey' themed credential + MFA token capture | 2026-09-09 | Microsoft (passkey-themed M365 phishing research) |
| mfs-0081 | Microsoft 365 | AiTM 'oskey sync' passkey-setup lure via IT impersonation | 2026-09-09 | Microsoft (passkey-themed M365 phishing research) |
| mfs-0082 | Microsoft 365 | OAuth device-code phishing via compromised legit domain (staged gate → device auth) | 2026-09-10 | idacyber1 device-code phishing analysis (GitHub) |
| mfs-0083 | Microsoft 365 | Cloudflare Workers token-harvester backend for device-code phishing (?email= prefill) | 2026-09-10 | idacyber1 device-code phishing analysis (GitHub) |
| mfs-0117 | Microsoft 365 | Blob-URL / browser-in-browser phishing loaded via Microsoft OAuth+Teams redirect chain | 2026-09-09 | Barracuda / Cybersecurity News |
| mfs-0122 | Microsoft 365 / Entra ID | Passkey/SSO-themed credential + session phishing (passkey-themed M365 data-theft wave) | 2026-09-09 | Cyber Security News |
| mfs-0123 | Microsoft 365 / Entra ID | Passkey/key-sync lure phishing impersonating M365 sign-in / passkey setup | 2026-09-09 | Cyber Security News |
| mfs-0124 | Microsoft 365 / Entra ID | Passkey/SSO connect-key themed AiTM phishing for M365 credentials/session | 2026-09-09 | Cyber Security News |
| mfs-0125 | Microsoft 365 / Entra ID | Passkey-themed phishing (oskey* family) mimicking Microsoft passkey enrollment | 2026-09-09 | Cyber Security News |
| mfs-0126 | Microsoft 365 / Entra ID | Account-validation/setup themed M365 credential phishing (passkey campaign) | 2026-09-09 | Cyber Security News |

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

### mfs-0019 — Microsoft 365

```text
https://notifications.microsoft-ssl.com
```

- **Domain:** `notifications.microsoft-ssl.com`
- **Technique:** typosquat credential-harvest domain ("microsoft-ssl" impersonation)
- **Detection:** Alert on newly-registered domains containing 'microsoft' + 'ssl'/'secure' keywords in cert transparency logs
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-04

### mfs-0020 — Microsoft Outlook / Office 365

```text
http://login-outlook365.yzz.me
```

- **Domain:** `login-outlook365.yzz.me`
- **Technique:** typosquat login page on free subdomain host (yzz.me)
- **Detection:** Block/flag 'login-outlook365' and Outlook-brand strings on free dynamic-DNS/subdomain hosts
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0021 — Microsoft OneDrive

```text
https://grupoimpaktu.ao/quotesss/onedrive-verify-obf.html
```

- **Domain:** `grupoimpaktu.ao`
- **Technique:** compromised legit site hosting obfuscated HTML credential page
- **Detection:** Hunt for '*-obf.html' / '*-verify*.html' under unexpected paths (e.g. /quotesss/) on non-Microsoft domains
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0022 — Microsoft 365

```text
https://login.authorised-support.com/microsoft365/mfa/
```

- **Domain:** `login.authorised-support.com`
- **Technique:** AiTM/MFA-relay lure on 'support'-themed lookalike domain
- **Detection:** Flag '/microsoft365/mfa/' paths on domains impersonating support/helpdesk brands
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-08-30

### mfs-0024 — Microsoft

```text
http://bmb.adv.br/meetings/microsoft-store.html
```

- **Domain:** `bmb.adv.br`
- **Technique:** compromised Brazilian law-firm site hosting fake 'microsoft-store' page
- **Detection:** Hunt for 'microsoft-store.html' / Microsoft-brand HTML under /meetings/ on unrelated domains
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0025 — Microsoft Word / Office 365

```text
https://microsoftwordob.blogspot.com
```

- **Domain:** `microsoftwordob.blogspot.com`
- **Technique:** abuse of Blogspot free hosting for brand-impersonation landing page
- **Detection:** Flag *.blogspot.com subdomains containing 'microsoft'/'word'/'office' tokens
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-01

### mfs-0026 — Microsoft 365

```text
https://microsoft0117.vercel.app
```

- **Domain:** `microsoft0117.vercel.app`
- **Technique:** abuse of Vercel hosting for Microsoft-branded phishing app
- **Detection:** Alert on *.vercel.app / *.workers.dev subdomains containing 'microsoft' + digits
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-08-28

### mfs-0027 — Microsoft Outlook

```text
https://proteccion-outlook2026.iceiy.com/?i=1
```

- **Domain:** `proteccion-outlook2026.iceiy.com`
- **Technique:** typosquat credential-harvest landing page ('proteccion-outlook2026')
- **Detection:** Alert on iceiy.com free-hosting subdomains containing 'outlook'/'office' with ?i= query param
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-13

### mfs-0028 — Microsoft 365

```text
https://advancedplacyncement.vu/
```

- **Domain:** `advancedplacyncement.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365/SharePoint/Teams login for token theft
- **Detection:** Hunt .vu TLD sites using Cloudflare Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W or beaconing to console 104.37.188.94
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0029 — Microsoft 365

```text
https://amstardmzsmc.vu/
```

- **Domain:** `amstardmzsmc.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for session-token theft
- **Detection:** Hunt .vu TLD sites using Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W or Tencent Cloud token-replay IPs (43.x/170.106.x/162.62.x/49.51.x)
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0030 — Microsoft 365

```text
https://arandasoftzfdware.vu/
```

- **Domain:** `arandasoftzfdware.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt randomized-string .vu domains with Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0031 — Microsoft 365

```text
https://avisoretentiunionllc.vu/
```

- **Domain:** `avisoretentiunionllc.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains resolving near Knight Office console 104.37.188.94
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0032 — Microsoft 365

```text
https://capitalflwxinancialpartners.vu/
```

- **Domain:** `capitalflwxinancialpartners.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt business-themed .vu domains with embedded Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0033 — Microsoft 365

```text
https://certififiycationedge.vu/
```

- **Domain:** `certififiycationedge.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu TLD with doubled/garbled brand words + Turnstile challenge
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0034 — Microsoft 365

```text
https://connectivnqzityltd.vu/
```

- **Domain:** `connectivnqzityltd.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with random consonant clusters serving M365 login clones
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0035 — Microsoft 365

```text
https://crrbcearegroup.vu/
```

- **Domain:** `crrbcearegroup.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0036 — Microsoft 365

```text
https://digitaltrafwwrficsystems.vu/
```

- **Domain:** `digitaltrafwwrficsystems.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu TLD phishing hosts fronted by Cloudflare Turnstile
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0037 — Microsoft 365

```text
https://exceltecbusinessbwpsolutions.vu/
```

- **Domain:** `exceltecbusinessbwpsolutions.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt long business-name .vu domains with garbled infixes
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0038 — Microsoft 365

```text
https://genamewwgdiamarketing.vu/
```

- **Domain:** `genamewwgdiamarketing.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0039 — Microsoft 365

```text
https://globaieflsoftinc.vu/
```

- **Domain:** `globaieflsoftinc.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu TLD with random-string brand impersonation + M365 login clone
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0040 — Microsoft 365

```text
https://globalmixeucbdmodetechnologyinc.vu/
```

- **Domain:** `globalmixeucbdmodetechnologyinc.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt overly long .vu domains beaconing to 104.37.188.94
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0041 — Microsoft 365

```text
https://globalprojectspvtltd.vu/
```

- **Domain:** `globalprojectspvtltd.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt corporate-suffix (pvtltd/llc/inc) .vu domains serving M365 login
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0042 — Microsoft 365

```text
https://joinbusinessmanagementconsdjeulting.vu/
```

- **Domain:** `joinbusinessmanagementconsdjeulting.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with garbled infix + Turnstile challenge page
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0043 — Microsoft 365

```text
https://kentmanqhfufacturingcompany.vu/
```

- **Domain:** `kentmanqhfufacturingcompany.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0044 — Microsoft 365

```text
https://kleepxrnlinecorporation.vu/
```

- **Domain:** `kleepxrnlinecorporation.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt random-string .vu 'corporation' domains fronted by Turnstile
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0045 — Microsoft 365

```text
https://knsinternacshtional.vu/
```

- **Domain:** `knsinternacshtional.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with garbled 'international' spelling + M365 clone
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0046 — Microsoft 365

```text
https://monttmmlrustcompany.vu/
```

- **Domain:** `monttmmlrustcompany.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains beaconing to Knight Office console 104.37.188.94
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0047 — Microsoft 365

```text
https://mtprormtductions.vu/
```

- **Domain:** `mtprormtductions.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt short garbled .vu domains with Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0048 — Microsoft 365

```text
https://realestatecotblrp.vu/
```

- **Domain:** `realestatecotblrp.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with random trailing consonants serving M365 login
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0049 — Microsoft 365

```text
https://siottxgroup.vu/
```

- **Domain:** `siottxgroup.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt short random-string .vu 'group' domains fronted by Turnstile
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0050 — Microsoft 365

```text
https://summitcapitaltrapojininggroup.vu/
```

- **Domain:** `summitcapitaltrapojininggroup.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt long finance-themed .vu domains with garbled infixes
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0051 — Microsoft 365

```text
https://techcompositnkoes.vu/
```

- **Domain:** `techcompositnkoes.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt .vu domains with Turnstile sitekey 0x4AAAAAADrkE-VuOnNDfr6W
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0052 — Microsoft 365

```text
https://techromixsolutionlonsinc.vu/
```

- **Domain:** `techromixsolutionlonsinc.vu`
- **Technique:** AiTM (Knight Office kit) proxying M365 login for token theft
- **Detection:** Hunt tech/solutions-themed .vu domains with garbled spelling + M365 clone
- **Source:** Huntress — https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
- **Status:** active
- **First seen:** 2026-09-02

### mfs-0056 — Microsoft Entra ID

```text
https://passkeyhelpdesk.com/
```

- **Domain:** `passkeyhelpdesk.com`
- **Technique:** IT-help-desk vishing + passkey-enrollment AiTM (O-UNC-066 'Pink')
- **Detection:** Alert on Entra passkey/FIDO2 registration from unfamiliar device right after inbound support call; watch domains with 'passkey'/'helpdesk'/'sso' tokens
- **Source:** The Hacker News — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0057 — Microsoft Entra ID

```text
https://secure-passkey.com/
```

- **Domain:** `secure-passkey.com`
- **Technique:** Passkey-themed AiTM phishing mimicking Microsoft sign-in via SMS lures
- **Detection:** Monitor for new 'passkey' registrations and add-security-info events; block secure-passkey/setupmypasskey/add-passkey domain family
- **Source:** The Hacker News — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0058 — Microsoft 365

```text
https://setupmypasskey.com/
```

- **Domain:** `setupmypasskey.com`
- **Technique:** Passkey-enrollment phishing directing users to counterfeit Microsoft sign-in
- **Detection:** Correlate SMS-delivered links with sign-ins from residential-proxy ASNs; flag 'setupmypasskey'/'syncmykey' lookalikes
- **Source:** The Hacker News — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0059 — Microsoft Entra ID

```text
https://add-passkey.com/
```

- **Domain:** `add-passkey.com`
- **Technique:** Fake passkey-setup portal harvesting Microsoft creds/session
- **Detection:** Trigger on passkey enrollment immediately following a phishing-domain visit; blocklist 'add-passkey'/'portalsetuphub' family
- **Source:** The Hacker News — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0060 — Microsoft 365

```text
https://portalsetuphub.com/
```

- **Domain:** `portalsetuphub.com`
- **Technique:** Counterfeit Microsoft portal-setup page in passkey/SSO vishing campaign
- **Detection:** Hunt 'portalsetup'/'portalhub' newly-registered domains proxying to Microsoft login; review new device+passkey binds in Entra audit logs
- **Source:** The Hacker News — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0068 — Microsoft OneDrive

```text
https://odahlzr5lm.reliabilityinoperations.de
```

- **Domain:** `odahlzr5lm.reliabilityinoperations.de`
- **Technique:** fake OneDrive document portal harvesting M365 creds (Google/Cloudflare infra abuse)
- **Detection:** Random 10-char subdomain on unrelated .de apex serving OneDrive-branded login; check for interstitial CAPTCHA gate
- **Source:** GBHackers — https://gbhackers.com/global-phishing-campaign/
- **Status:** active
- **First seen:** 2026-09-01

### mfs-0069 — Microsoft 365

```text
https://cloudbemismanufacturingcompanygroup.rydezyhrsysteminc.vu
```

- **Domain:** `cloudbemismanufacturingcompanygroup.rydezyhrsysteminc.vu`
- **Technique:** M365 credential harvester behind interstitial gate (.vu abuse)
- **Detection:** Long company-name subdomains on .vu apexes; block *.rydezyhrsysteminc.vu and hunt interstitial 'verify' gates before login
- **Source:** GBHackers — https://gbhackers.com/global-phishing-campaign/
- **Status:** active
- **First seen:** 2026-09-01

### mfs-0070 — Microsoft Teams / 365

```text
https://crsons.net/wp-includes/js/tinymce/
```

- **Domain:** `crsons.net`
- **Technique:** compromised WordPress site hiding M365/Teams phishing kit in legit dirs
- **Detection:** Alert on login pages served from /wp-includes/js/tinymce/ paths on compromised WP sites
- **Source:** GBHackers — https://gbhackers.com/hackers-abuse-trusted-websites-in-new-attacks/
- **Status:** active
- **First seen:** 2026-09-01

### mfs-0071 — Microsoft Teams / 365

```text
https://afghantarin.com/afghantarin/admin/waitme/
```

- **Domain:** `afghantarin.com`
- **Technique:** compromised-site phishing kit in nested admin path
- **Detection:** Hunt 'waitme'/loader interstitials under /admin/ paths on compromised sites chaining to Microsoft login
- **Source:** GBHackers — https://gbhackers.com/hackers-abuse-trusted-websites-in-new-attacks/
- **Status:** active
- **First seen:** 2026-09-01

### mfs-0072 — Microsoft 365 / Outlook

```text
https://cabinetzeukeng.net/config/.bin/voicemail
```

- **Domain:** `cabinetzeukeng.net`
- **Technique:** voicemail-lure phishing kit hidden in /config/.bin/ backend dir
- **Detection:** Flag 'voicemail' pages under dot-prefixed backend dirs (/.bin/, /config/) that post creds to non-Microsoft hosts
- **Source:** GBHackers — https://gbhackers.com/hackers-abuse-trusted-websites-in-new-attacks/
- **Status:** active
- **First seen:** 2026-09-01

### mfs-0073 — Microsoft 365

```text
https://assignpasskey.com/
```

- **Domain:** `assignpasskey.com`
- **Technique:** AiTM passkey/SSO-themed vishing lure (help-desk impersonation, victim-specific subdomains capture creds + MFA tokens)
- **Detection:** Hunt newly-registered domains (esp. Nicenic registrar) containing passkey/oskey/sso keywords; alert on company-name subdomains like companyname.assignpasskey.com
- **Source:** Arctic Wolf (PREY-0058 / Cordial Spider) — https://arcticwolf.com/resources/blog/security-bulletin-active-cloud-data-theft-and-extortion-campaign-targeting-microsoft-365-and-saas-platforms/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0074 — Microsoft 365

```text
https://mfaregister.com/
```

- **Domain:** `mfaregister.com`
- **Technique:** AiTM passkey/MFA re-enrollment lure via IT help-desk vishing
- **Detection:** Flag auth-themed domains combining 'mfa'+'register'; correlate with token replay from residential-proxy ASNs
- **Source:** Arctic Wolf (PREY-0058 / Cordial Spider) — https://arcticwolf.com/resources/blog/security-bulletin-active-cloud-data-theft-and-extortion-campaign-targeting-microsoft-365-and-saas-platforms/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0075 — Microsoft 365

```text
https://nowsso.com/
```

- **Domain:** `nowsso.com`
- **Technique:** AiTM SSO-setup lure (Microsoft 365 / Okta-Duo credential + MFA capture)
- **Detection:** Alert on short SSO-themed domains ('nowsso') resolving to victim-named subdomains; monitor bulk SharePoint/mailbox access post-login
- **Source:** Arctic Wolf (PREY-0058 / Cordial Spider) — https://arcticwolf.com/resources/blog/security-bulletin-active-cloud-data-theft-and-extortion-campaign-targeting-microsoft-365-and-saas-platforms/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0076 — Microsoft 365

```text
https://oskeysetup.com/
```

- **Domain:** `oskeysetup.com`
- **Technique:** AiTM 'oskey/passkey setup' lure delivered via voice phishing
- **Detection:** Hunt 'oskey*' / 'setpasskey' domain patterns; watch for MFA token replay from anomalous geo/proxy
- **Source:** Arctic Wolf (PREY-0058 / Cordial Spider) — https://arcticwolf.com/resources/blog/security-bulletin-active-cloud-data-theft-and-extortion-campaign-targeting-microsoft-365-and-saas-platforms/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0077 — Microsoft 365

```text
https://passkey-mfa.com/
```

- **Domain:** `passkey-mfa.com`
- **Technique:** AiTM passkey+MFA themed credential/token harvester
- **Detection:** Block/monitor 'passkey-mfa' and sibling passkey/oskey infra; detect impossible-travel token use
- **Source:** Arctic Wolf (PREY-0058 / Cordial Spider) — https://arcticwolf.com/resources/blog/security-bulletin-active-cloud-data-theft-and-extortion-campaign-targeting-microsoft-365-and-saas-platforms/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0078 — Microsoft 365

```text
https://integratedsso.com/
```

- **Domain:** `integratedsso.com`
- **Technique:** AiTM SSO-integration lure with victim-company subdomains (companyname.integratedsso.com)
- **Detection:** Alert on 'integratedsso' subdomains embedding tenant/company names; correlate with residential-proxy sign-ins
- **Source:** Microsoft / Arctic Wolf (PREY-0058) — https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0079 — Microsoft 365 / Okta

```text
https://oktasession.com/
```

- **Domain:** `oktasession.com`
- **Technique:** AiTM SSO-session lure impersonating Microsoft/Okta sign-in during help-desk vishing
- **Detection:** Hunt 'oktasession'/'*session' auth domains; flag token replay lacking device compliance
- **Source:** Microsoft (passkey-themed M365 phishing research) — https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0080 — Microsoft 365

```text
https://keysyncos.com/
```

- **Domain:** `keysyncos.com`
- **Technique:** AiTM 'key sync/passkey' themed credential + MFA token capture
- **Detection:** Block 'keysyncos'/'oskeysync' cluster; monitor newly-registered auth-keyword domains via Nicenic
- **Source:** Microsoft (passkey-themed M365 phishing research) — https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0081 — Microsoft 365

```text
https://oskeysync.com/
```

- **Domain:** `oskeysync.com`
- **Technique:** AiTM 'oskey sync' passkey-setup lure via IT impersonation
- **Detection:** Alert on oskey*/keysync* domain family; detect SharePoint discovery + mailbox harvesting after login
- **Source:** Microsoft (passkey-themed M365 phishing research) — https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0082 — Microsoft 365

```text
https://indecodesign.net/accessportal/safe.html
```

- **Domain:** `indecodesign.net`
- **Technique:** OAuth device-code phishing via compromised legit domain (staged gate → device auth)
- **Detection:** Alert on entra sign-in logs showing device-code grant from unusual ASN shortly after user visits *.html pages on aged/compromised domains; hunt referers to microsoft.com/devicelogin
- **Source:** idacyber1 device-code phishing analysis (GitHub) — https://github.com/idacyber1/devicecode-phishing-analysis/blob/main/ANALYSIS.md
- **Status:** active
- **First seen:** 2026-09-10

### mfs-0083 — Microsoft 365

```text
https://jzqs-udkz-yhxx.hutton-aasir-dropons-com-s-account.workers.dev/
```

- **Domain:** `jzqs-udkz-yhxx.hutton-aasir-dropons-com-s-account.workers.dev`
- **Technique:** Cloudflare Workers token-harvester backend for device-code phishing (?email= prefill)
- **Detection:** Block/monitor random-subdomain *.workers.dev with '?email=' query targeting O365 users; flag Workers accounts hosting device-code relays
- **Source:** idacyber1 device-code phishing analysis (GitHub) — https://github.com/idacyber1/devicecode-phishing-analysis/blob/main/ANALYSIS.md
- **Status:** active
- **First seen:** 2026-09-10

### mfs-0117 — Microsoft 365

```text
https://cdn.bloom.io
```

- **Domain:** `cdn.bloom.io`
- **Technique:** Blob-URL / browser-in-browser phishing loaded via Microsoft OAuth+Teams redirect chain
- **Detection:** Flag Teams/OAuth redirect chains fetching external JS from cdn.bloom.io then rendering blob: login pages; alert on blob URL credential forms
- **Source:** Barracuda / Cybersecurity News — https://cybersecuritynews.com/hackers-use-blob-urls/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0122 — Microsoft 365 / Entra ID

```text
https://oskeyregister.com/
```

- **Domain:** `oskeyregister.com`
- **Technique:** Passkey/SSO-themed credential + session phishing (passkey-themed M365 data-theft wave)
- **Detection:** Block *oskey* / *key-register* NRDs; alert on M365 sign-ins with new passkey registration from proxy/VPS IPs
- **Source:** Cyber Security News — https://cybersecuritynews.com/passkey-themed-phishing/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0123 — Microsoft 365 / Entra ID

```text
https://syncmykey.com/
```

- **Domain:** `syncmykey.com`
- **Technique:** Passkey/key-sync lure phishing impersonating M365 sign-in / passkey setup
- **Detection:** Flag newly-registered *synckey*/*mykey* domains; hunt referrers ending in syncmykey.com hitting login.microsoftonline.com
- **Source:** Cyber Security News — https://cybersecuritynews.com/passkey-themed-phishing/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0124 — Microsoft 365 / Entra ID

```text
https://myconnectkey.com/
```

- **Domain:** `myconnectkey.com`
- **Technique:** Passkey/SSO connect-key themed AiTM phishing for M365 credentials/session
- **Detection:** Block *connectkey* NRDs; correlate with anomalous Entra passkey/MFA method additions post-visit
- **Source:** Cyber Security News — https://cybersecuritynews.com/passkey-themed-phishing/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0125 — Microsoft 365 / Entra ID

```text
https://oskeyconnect.com/
```

- **Domain:** `oskeyconnect.com`
- **Technique:** Passkey-themed phishing (oskey* family) mimicking Microsoft passkey enrollment
- **Detection:** Add oskey* domain family (oskeysync/oskeysetup/oskeyconnect/oskeyregister) to blocklist; alert on shared TLS cert/hosting reuse
- **Source:** Cyber Security News — https://cybersecuritynews.com/passkey-themed-phishing/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0126 — Microsoft 365 / Entra ID

```text
https://validationsetupac.com/
```

- **Domain:** `validationsetupac.com`
- **Technique:** Account-validation/setup themed M365 credential phishing (passkey campaign)
- **Detection:** Flag *validationsetup* / *setupac* NRDs; hunt for these hostnames as HTTP referrers to Microsoft auth endpoints
- **Source:** Cyber Security News — https://cybersecuritynews.com/passkey-themed-phishing/
- **Status:** active
- **First seen:** 2026-09-09

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["microsoft-advertising-authentification.sgn-1.com", "emanuelabsoluciones.com", "microsoft-alpha.vercel.app", "watco.microsoft-notifcation.com", "50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document.workers.dev", "aquaclaude-09494-9099403-docviewer.clear90489058903-document.workers.dev", "spx.pamconj.com", "login-microsoft-0nline.ts.r.appspot.com", "login-microsoft-outlook.el.r.appspot.com", "tlook-off365-signin.el.r.appspot.com", "xmaksvwq.wze.io", "noithatviet24h.vn", "newprojectdocument.uc.r.appspot.com", "onedrivelinkedindocument.oa.r.appspot.com", "spherical-door-277805.uc.r.appspot.com", "voicemail365.nn.r.appspot.com", "office365-portal-verify.el.r.appspot.com", "loginblxxslingfbvfgh600ohjm.ga", "notifications.microsoft-ssl.com", "login-outlook365.yzz.me", "grupoimpaktu.ao", "login.authorised-support.com", "bmb.adv.br", "microsoftwordob.blogspot.com", "microsoft0117.vercel.app", "proteccion-outlook2026.iceiy.com", "advancedplacyncement.vu", "amstardmzsmc.vu", "arandasoftzfdware.vu", "avisoretentiunionllc.vu", "capitalflwxinancialpartners.vu", "certififiycationedge.vu", "connectivnqzityltd.vu", "crrbcearegroup.vu", "digitaltrafwwrficsystems.vu", "exceltecbusinessbwpsolutions.vu", "genamewwgdiamarketing.vu", "globaieflsoftinc.vu", "globalmixeucbdmodetechnologyinc.vu", "globalprojectspvtltd.vu", "joinbusinessmanagementconsdjeulting.vu", "kentmanqhfufacturingcompany.vu", "kleepxrnlinecorporation.vu", "knsinternacshtional.vu", "monttmmlrustcompany.vu", "mtprormtductions.vu", "realestatecotblrp.vu", "siottxgroup.vu", "summitcapitaltrapojininggroup.vu", "techcompositnkoes.vu", "techromixsolutionlonsinc.vu", "passkeyhelpdesk.com", "secure-passkey.com", "setupmypasskey.com", "add-passkey.com", "portalsetuphub.com", "odahlzr5lm.reliabilityinoperations.de", "cloudbemismanufacturingcompanygroup.rydezyhrsysteminc.vu", "crsons.net", "afghantarin.com", "cabinetzeukeng.net", "assignpasskey.com", "mfaregister.com", "nowsso.com", "oskeysetup.com", "passkey-mfa.com", "integratedsso.com", "oktasession.com", "keysyncos.com", "oskeysync.com", "indecodesign.net", "jzqs-udkz-yhxx.hutton-aasir-dropons-com-s-account.workers.dev", "cdn.bloom.io", "oskeyregister.com", "syncmykey.com", "myconnectkey.com", "oskeyconnect.com", "validationsetupac.com"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

