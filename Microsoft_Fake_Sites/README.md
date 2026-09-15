# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 149
- **Retention:** rolling 30 days
- **Last updated:** 2026-09-15
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
| mfs-0132 | Microsoft Entra ID | vishing/help-desk lure domain using <org>.oursso.com pattern for AiTM sign-in | 2026-09-07 | Arctic Wolf via The Hacker News (PREY-0058) |
| mfs-0133 | Microsoft Entra ID | passkey/MFA-enrollment themed vishing lure (<org>.passkeydeploy.com) driving AiTM | 2026-09-07 | Arctic Wolf via The Hacker News (PREY-0058) |
| mfs-0134 | Microsoft Entra ID | MFA-registration themed help-desk lure domain for AiTM credential/token capture | 2026-09-07 | Arctic Wolf via The Hacker News (PREY-0058) |
| mfs-0135 | Microsoft Entra ID | passkey-setup themed vishing lure (<org>.setpasskey.com) into AiTM sign-in flow | 2026-09-07 | Arctic Wolf via The Hacker News (PREY-0058) |
| mfs-0136 | Microsoft (Microsoft Online) | IDN/punycode homograph typosquat (renders as micrósoftonline) | 2026-09-09 | phishunt.io (newly-registered Microsoft phishing domains) |
| mfs-0137 | Microsoft 365 (login.microsoftonline.com) | typosquat / brand-plus-keyword ('recovery') credential-reset lure | 2026-09-12 | phishunt.io |
| mfs-0138 | Microsoft 365 / Azure AD OAuth | typosquat impersonating login.microsoftonline.com/common/oauth2 endpoint | 2026-09-08 | phishunt.io |
| mfs-0139 | Microsoft Outlook | leetspeak typosquat (zero-for-o) of outlook.com | 2026-09-11 | phishunt.io |
| mfs-0140 | Microsoft Outlook | leetspeak typosquat of outlook on cheap .store TLD | 2026-09-11 | phishunt.io |
| mfs-0141 | Microsoft Outlook | leetspeak typosquat of outlook on .site TLD | 2026-09-11 | phishunt.io |
| mfs-0142 | Microsoft 365 MFA | typosquat MFA-themed lure (AiTM MFA fatigue / passkey enrollment) | 2026-09-09 | phishunt.io |
| mfs-0143 | Microsoft 365 authentication | typosquat auth-verification credential lure | 2026-09-07 | phishunt.io |
| mfs-0144 | Microsoft 365 / Office 365 (IdP / federation) | typosquat impersonating an Office365 identity-provider / ADFS sign-in | 2026-09-08 | phishunt.io |
| mfs-0145 | Microsoft 365 / Outlook Web mail | typosquat Office365 webmail sign-in lure | 2026-09-11 | phishunt.io |
| mfs-0146 | Microsoft 365 | typosquat brand-stuffed domain on .cloud TLD | 2026-09-12 | phishunt.io |
| mfs-0147 | Microsoft Forms | deceptive-subdomain typosquat mimicking a forms.microsoft.com response-page URL ('https-' prefix to fake the scheme) | 2026-09-12 | phishunt.io |
| mfs-0148 | Microsoft OneDrive | typosquat OneDrive shared-document credential lure | 2026-09-11 | phishunt.io |
| mfs-0149 | Microsoft OneDrive | typosquat OneDrive 'shared PDF' document-lure on .work TLD | 2026-09-08 | phishunt.io |
| mfs-0150 | Microsoft Teams | typosquat Teams 'meeting booking' redirect/AiTM lure | 2026-09-09 | phishunt.io |
| mfs-0151 | Microsoft Teams | typosquat Teams booking lure on .top TLD | 2026-09-08 | phishunt.io |
| mfs-0152 | Microsoft Teams | typosquat (dropped 't', 'microsofteams') on .live TLD | 2026-09-08 | phishunt.io |
| mfs-0153 | Microsoft Outlook / Office 365 | typosquat mail-server 'all servers' credential lure on .help TLD | 2026-09-09 | phishunt.io |
| mfs-0154 | Microsoft Outlook support | typosquat 'support' tech-support/credential lure | 2026-09-09 | phishunt.io |
| mfs-0155 | Microsoft support | typosquat tech-support-scam / credential lure | 2026-09-11 | phishunt.io |
| mfs-0156 | Microsoft support | typosquat 'secure help' credential/tech-support lure | 2026-09-11 | phishunt.io |
| mfs-0157 | Microsoft | algorithmic/numeric-suffix throwaway typosquat (kit-generated) | 2026-09-08 | phishunt.io |
| mfs-0158 | Microsoft | numeric-prefix throwaway typosquat (kit-generated) | 2026-09-11 | phishunt.io |
| mfs-0159 | Microsoft Outlook | typosquat (brand+version-number) sign-in lure | 2026-09-13 | phishunt.io |
| mfs-0160 | Microsoft Outlook | leetspeak typosquat (zero-for-o) of outlook.com | 2026-09-13 | phishunt.io |
| mfs-0161 | Microsoft OneDrive | character-repetition typosquat ('onedrivee') | 2026-09-13 | phishunt.io |
| mfs-0162 | Microsoft 365 | AiTM credential/session proxy (token in /i/<hex> path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0163 | Microsoft 365 | Typosquat + AiTM (m365-microsoft.com subdomains, /i/ token path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0164 | Microsoft | Typosquat/subdomain deception (email-microsoft.com) credential harvest | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0165 | Microsoft 365 | AiTM phishing kit (m365-microsoft.com, /i/ token path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0166 | Microsoft 365 | AiTM phishing kit (m365-microsoft.com, /i/ token path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0167 | Microsoft 365 | AiTM phishing kit (m365-microsoft.com, /i/ token path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0168 | Microsoft Live | Free-hosting (iceiy) Spanish 'reactivar cuenta' account-reactivation lure | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0169 | Microsoft | Typosquat on free eu.org subdomain | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0170 | Microsoft | Free-hosting (Jimdo) fake login page | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0171 | Microsoft | Tech-support-themed typosquat (.digital TLD, clickN subdomains) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0172 | Microsoft | Tech-support-themed typosquat (.digital TLD, clickN subdomains) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0173 | Microsoft | Typosquat brand domain (.us) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0174 | Microsoft | Subdomain deception ('microsoft' label on attacker apex) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0175 | Microsoft 365 | AiTM kit on authorised-support.com (base64-like token path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0176 | Microsoft 365 | Typosquat brand/product domain | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0177 | Office 365 | Typosquat (licensing/support themed brand domain) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0178 | Microsoft 365 | Typosquat (update-themed brand domain) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0179 | Microsoft | Typosquat (www-microsoft hyphen trick, .com.cn) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0180 | Microsoft SharePoint | Typosquat SharePoint brand domain (.fr) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0181 | Microsoft | Typosquat brand domain (.co) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0182 | Microsoft | Subdomain deception ('microsoft' label on vpn-update.org) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0183 | Outlook / Office 365 | Typosquat combining outlook+office365 brand terms | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0184 | Outlook | AiTM (outlook subdomain, /s/<id>/<uuid> tracked victim path) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0185 | Outlook | AiTM (outlook subdomain, same /s/ per-victim token path as webaccess-alert.com) | 2026-09-14 | phishunt.io (OpenPhish) |
| mfs-0186 | Office 365 | homoglyph typosquat (rn→m 'rricrosoft') with tokenized /i/<32-hex> AiTM tracking path | 2026-09-15 | phishunt.io |
| mfs-0187 | Microsoft 365 | brand-impersonation typosquat domain (licensing/tech-support lure) | 2026-09-15 | phishunt.io |
| mfs-0188 | OneDrive | subdomain spoof ('onedrive.*' label on unrelated base domain) with long token and #/ SPA fragment | 2026-09-15 | phishunt.io |
| mfs-0189 | Outlook | brand-keyword typosquat on cheap TLD (.social) | 2026-09-15 | phishunt.io |
| mfs-0190 | Outlook | lookalike domain embedding 'outlook' brand keyword | 2026-09-15 | phishunt.io |
| mfs-0191 | Microsoft (Hotmail/Live) | typosquat of Hotmail/Live consumer brand (brand+digits) | 2026-09-15 | phishunt.io |
| mfs-0192 | OneDrive / Office 365 | compromised legitimate site hosting obfuscated OneDrive 'verify' HTML credential page | 2026-09-15 | OpenPhish |
| mfs-0193 | Outlook / Exchange (OWA) | lookalike domain serving a fake Outlook Web Access /owa/ login | 2026-09-15 | OpenPhish |
| mfs-0194 | Office 365 | typosquat ('oficeer') on free app-hosting platform (replit.app) | 2026-09-15 | OpenPhish |
| mfs-0195 | Microsoft (Outlook/Hotmail) | Credential-harvesting fake sign-in that proxies a real Microsoft OAuth authorize flow (client_id 4765445b-32c6-49b0-83e6-1d93765276ca) redirecting to office.com/landingv2 to look legitimate | 2026-09-15 | OpenPhish public feed |
| mfs-0196 | Microsoft Outlook / Office 365 | Outlook-2026-themed credential phishing hosted on abused legitimate SaaS platform (Yapla) | 2026-09-15 | phishunt.io / OpenPhish |
| mfs-0197 | Microsoft 365 (webmail) | AWS S3-hosted static credential-harvest page (log.html) with victim email pre-seeded in the URL fragment to auto-populate the fake Microsoft login | 2026-09-10 | TweetFeed / @muha2xmad (X) |
| mfs-0198 | Microsoft Entra ID / 365 | Help-desk social-engineering into rogue passkey/MFA enrollment (O-UNC-066); per-victim subdomains like <company>.deploypasskey.com | 2026-09-15 | PurpleSec (O-UNC-066 passkey campaign) |
| mfs-0199 | Microsoft Entra ID / 365 | Rogue passkey-enrollment lure (O-UNC-066); tricks victims into adding an attacker-controlled passkey to their Microsoft account | 2026-09-15 | PurpleSec (O-UNC-066 passkey campaign) |
| mfs-0200 | Microsoft 365 | typosquat (microsoftonnline) on free Jimdo hosting | 2026-09-15 | OpenPhish |
| mfs-0201 | Microsoft Office 365 | lookalike 'office' subdomain credential-harvest page | 2026-09-15 | OpenPhish |
| mfs-0202 | Microsoft 365 | SSO-themed lookalike subdomain on shared phishing infrastructure | 2026-09-15 | OpenPhish |

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

### mfs-0132 — Microsoft Entra ID

```text
https://oursso.com/
```

- **Domain:** `oursso.com`
- **Technique:** vishing/help-desk lure domain using <org>.oursso.com pattern for AiTM sign-in
- **Detection:** Block *.oursso.com; alert on Entra sign-ins preceded by help-desk phone contact and rogue device registration
- **Source:** Arctic Wolf via The Hacker News (PREY-0058) — https://thehackernews.com/2026/09/microsoft-365-attackers-use-help-desk.html
- **Status:** active
- **First seen:** 2026-09-07

### mfs-0133 — Microsoft Entra ID

```text
https://passkeydeploy.com/
```

- **Domain:** `passkeydeploy.com`
- **Technique:** passkey/MFA-enrollment themed vishing lure (<org>.passkeydeploy.com) driving AiTM
- **Detection:** Block *.passkeydeploy.com; hunt unexpected Windows Hello for Business / passkey enrollments after inbound support calls
- **Source:** Arctic Wolf via The Hacker News (PREY-0058) — https://thehackernews.com/2026/09/microsoft-365-attackers-use-help-desk.html
- **Status:** active
- **First seen:** 2026-09-07

### mfs-0134 — Microsoft Entra ID

```text
https://registermymfa.com/
```

- **Domain:** `registermymfa.com`
- **Technique:** MFA-registration themed help-desk lure domain for AiTM credential/token capture
- **Detection:** Block *.registermymfa.com; alert on new MFA method registrations from unfamiliar devices/IPs post-vishing
- **Source:** Arctic Wolf via The Hacker News (PREY-0058) — https://thehackernews.com/2026/09/microsoft-365-attackers-use-help-desk.html
- **Status:** active
- **First seen:** 2026-09-07

### mfs-0135 — Microsoft Entra ID

```text
https://setpasskey.com/
```

- **Domain:** `setpasskey.com`
- **Technique:** passkey-setup themed vishing lure (<org>.setpasskey.com) into AiTM sign-in flow
- **Detection:** Block *.setpasskey.com; monitor for rogue device join + passkey credential add on Entra tenants
- **Source:** Arctic Wolf via The Hacker News (PREY-0058) — https://thehackernews.com/2026/09/microsoft-365-attackers-use-help-desk.html
- **Status:** active
- **First seen:** 2026-09-07

### mfs-0136 — Microsoft (Microsoft Online)

```text
https://xn--mcrosoftonlne-39bk.com
```

- **Domain:** `xn--mcrosoftonlne-39bk.com`
- **Technique:** IDN/punycode homograph typosquat (renders as micrósoftonline)
- **Detection:** Alert on any resolved DNS query or proxy request to xn--*.com decoding to a 'microsoft'/'microsoftonline' lookalike
- **Source:** phishunt.io (newly-registered Microsoft phishing domains) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0137 — Microsoft 365 (login.microsoftonline.com)

```text
https://microsoftonline-recovery.com
```

- **Domain:** `microsoftonline-recovery.com`
- **Technique:** typosquat / brand-plus-keyword ('recovery') credential-reset lure
- **Detection:** Flag newly-registered domains containing 'microsoftonline' as a substring outside *.microsoftonline.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0138 — Microsoft 365 / Azure AD OAuth

```text
https://microsoftonlinecommonoauth.com
```

- **Domain:** `microsoftonlinecommonoauth.com`
- **Technique:** typosquat impersonating login.microsoftonline.com/common/oauth2 endpoint
- **Detection:** Match domains concatenating 'microsoftonline'+'oauth'; compare against legit *.microsoftonline.com only
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0139 — Microsoft Outlook

```text
https://0utl00k.online
```

- **Domain:** `0utl00k.online`
- **Technique:** leetspeak typosquat (zero-for-o) of outlook.com
- **Detection:** Regex hunt for outlook lookalikes with digit substitutions: 0utl00k / 0utlook / outl00k
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0140 — Microsoft Outlook

```text
https://0utl00k.store
```

- **Domain:** `0utl00k.store`
- **Technique:** leetspeak typosquat of outlook on cheap .store TLD
- **Detection:** Same leet-Outlook regex across .online/.store/.site TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0141 — Microsoft Outlook

```text
https://0utl00k.site
```

- **Domain:** `0utl00k.site`
- **Technique:** leetspeak typosquat of outlook on .site TLD
- **Detection:** Same leet-Outlook regex across newly-registered domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0142 — Microsoft 365 MFA

```text
https://microsoftmultifactor.com
```

- **Domain:** `microsoftmultifactor.com`
- **Technique:** typosquat MFA-themed lure (AiTM MFA fatigue / passkey enrollment)
- **Detection:** Alert on domains combining 'microsoft'+'mfa'/'multifactor'/'authenticator'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0143 — Microsoft 365 authentication

```text
https://microsoftauthverify.com
```

- **Domain:** `microsoftauthverify.com`
- **Technique:** typosquat auth-verification credential lure
- **Detection:** Flag brand+('auth'|'verify'|'verification') newly-registered combos
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-07

### mfs-0144 — Microsoft 365 / Office 365 (IdP / federation)

```text
https://office365idp.com
```

- **Domain:** `office365idp.com`
- **Technique:** typosquat impersonating an Office365 identity-provider / ADFS sign-in
- **Detection:** Hunt office365+('idp'|'sso'|'adfs'|'federation') domains not on microsoft.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0145 — Microsoft 365 / Outlook Web mail

```text
https://office365mail.com
```

- **Domain:** `office365mail.com`
- **Technique:** typosquat Office365 webmail sign-in lure
- **Detection:** Flag office365+mail/webmail/owa lookalike domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0146 — Microsoft 365

```text
https://microsoft365online.cloud
```

- **Domain:** `microsoft365online.cloud`
- **Technique:** typosquat brand-stuffed domain on .cloud TLD
- **Detection:** Alert on 'microsoft365'+'online' concatenations on non-Microsoft TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0147 — Microsoft Forms

```text
https://https-forms-cloud-microsoft-pages-responsepage-a.link
```

- **Domain:** `https-forms-cloud-microsoft-pages-responsepage-a.link`
- **Technique:** deceptive-subdomain typosquat mimicking a forms.microsoft.com response-page URL ('https-' prefix to fake the scheme)
- **Detection:** Flag hostnames beginning with 'https-' or stuffing 'forms'+'microsoft'+'responsepage'; especially .link TLD
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-12

### mfs-0148 — Microsoft OneDrive

```text
https://onedrive-share.online
```

- **Domain:** `onedrive-share.online`
- **Technique:** typosquat OneDrive shared-document credential lure
- **Detection:** Hunt onedrive+('share'|'files'|'document') lookalike domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0149 — Microsoft OneDrive

```text
https://pdf-onedrivesharedfile.work
```

- **Domain:** `pdf-onedrivesharedfile.work`
- **Technique:** typosquat OneDrive 'shared PDF' document-lure on .work TLD
- **Detection:** Flag onedrive+sharedfile/pdf combos and .work TLD file-share lures
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0150 — Microsoft Teams

```text
https://microsoftteamsbooking.com
```

- **Domain:** `microsoftteamsbooking.com`
- **Technique:** typosquat Teams 'meeting booking' redirect/AiTM lure
- **Detection:** Hunt microsoftteams+('booking'|'meeting'|'invite') domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0151 — Microsoft Teams

```text
https://microsoftteambookingz.top
```

- **Domain:** `microsoftteambookingz.top`
- **Technique:** typosquat Teams booking lure on .top TLD
- **Detection:** Same Teams-booking pattern across cheap TLDs (.top/.live)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0152 — Microsoft Teams

```text
https://microsofteams.live
```

- **Domain:** `microsofteams.live`
- **Technique:** typosquat (dropped 't', 'microsofteams') on .live TLD
- **Detection:** Alert on 'microsofteams'/'microsoft-teams' outside teams.microsoft.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0153 — Microsoft Outlook / Office 365

```text
https://outlook365allservers.help
```

- **Domain:** `outlook365allservers.help`
- **Technique:** typosquat mail-server 'all servers' credential lure on .help TLD
- **Detection:** Hunt outlook365/office365 domains on .help/.support TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0154 — Microsoft Outlook support

```text
https://support-outlook.com
```

- **Domain:** `support-outlook.com`
- **Technique:** typosquat 'support' tech-support/credential lure
- **Detection:** Flag ('support'|'help'|'contact')+'outlook'/'microsoft' hyphenated domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-09

### mfs-0155 — Microsoft support

```text
https://contactsupport-microsoft.com
```

- **Domain:** `contactsupport-microsoft.com`
- **Technique:** typosquat tech-support-scam / credential lure
- **Detection:** Regex ('contact'|'help'|'helpssup'|'helpsecure')-microsoft.com newly-registered
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0156 — Microsoft support

```text
https://helpsecure-microsoft.com
```

- **Domain:** `helpsecure-microsoft.com`
- **Technique:** typosquat 'secure help' credential/tech-support lure
- **Detection:** Same helpX-microsoft.com hyphen pattern
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0157 — Microsoft

```text
https://microsoft251207.com
```

- **Domain:** `microsoft251207.com`
- **Technique:** algorithmic/numeric-suffix throwaway typosquat (kit-generated)
- **Detection:** Flag 'microsoft'+6-8 digit numeric-suffix newly-registered domains (e.g. microsoft251207, 676132-microsoft)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-08

### mfs-0158 — Microsoft

```text
https://676132-microsoft.com
```

- **Domain:** `676132-microsoft.com`
- **Technique:** numeric-prefix throwaway typosquat (kit-generated)
- **Detection:** Regex ^[0-9]{5,7}-microsoft\.com and microsoft-[0-9]{5,7} newly-registered
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0159 — Microsoft Outlook

```text
https://outlook10.net
```

- **Domain:** `outlook10.net`
- **Technique:** typosquat (brand+version-number) sign-in lure
- **Detection:** Flag outlook/hotmail + trailing digits (outlook10, hotmail10, hotmail1)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-13

### mfs-0160 — Microsoft Outlook

```text
https://outlo0k.com
```

- **Domain:** `outlo0k.com`
- **Technique:** leetspeak typosquat (zero-for-o) of outlook.com
- **Detection:** Levenshtein-1 permutations of 'outlook' with digit swaps
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-13

### mfs-0161 — Microsoft OneDrive

```text
https://onedrivee.online
```

- **Domain:** `onedrivee.online`
- **Technique:** character-repetition typosquat ('onedrivee')
- **Detection:** Detect doubled-letter permutations of onedrive/microsoft/outlook
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-13

### mfs-0162 — Microsoft 365

```text
https://office365.internal-alerts.com/i/d5b9af0d256f14c03ab8396a78d3687bf
```

- **Domain:** `office365.internal-alerts.com`
- **Technique:** AiTM credential/session proxy (token in /i/<hex> path)
- **Detection:** Alert on hostnames containing office365/m365 on non-Microsoft TLDs with a /i/<32-hex> URL path
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0163 — Microsoft 365

```text
http://support.m365-microsoft.com/i/ab041e84e499243eca3e98fb328201632
```

- **Domain:** `support.m365-microsoft.com`
- **Technique:** Typosquat + AiTM (m365-microsoft.com subdomains, /i/ token path)
- **Detection:** Block *.m365-microsoft.com; hunt DNS for 'm365-microsoft' brand-swap domains
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0164 — Microsoft

```text
https://security.email-microsoft.com/diyc_smavt1av3ltaq
```

- **Domain:** `security.email-microsoft.com`
- **Technique:** Typosquat/subdomain deception (email-microsoft.com) credential harvest
- **Detection:** Flag lookalike apex domains combining 'email'/'security' with 'microsoft'
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0165 — Microsoft 365

```text
https://programme-hup.m365-microsoft.com/i/d721e212eb3094bfd99c9d047a94edaeb
```

- **Domain:** `programme-hup.m365-microsoft.com`
- **Technique:** AiTM phishing kit (m365-microsoft.com, /i/ token path)
- **Detection:** Block *.m365-microsoft.com; monitor for /i/<hex> AiTM path pattern
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0166 — Microsoft 365

```text
http://security.m365-microsoft.com/i/d51ee024a6cb3468996ec7c9307051d1d
```

- **Domain:** `security.m365-microsoft.com`
- **Technique:** AiTM phishing kit (m365-microsoft.com, /i/ token path)
- **Detection:** Block *.m365-microsoft.com apex; correlate 'security' subdomain lures
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0167 — Microsoft 365

```text
http://emailnotifications.m365-microsoft.com/i/a3ce2879ab8b04bd4a96eaabe3f1dae68
```

- **Domain:** `emailnotifications.m365-microsoft.com`
- **Technique:** AiTM phishing kit (m365-microsoft.com, /i/ token path)
- **Detection:** Block *.m365-microsoft.com; alert on 'emailnotifications' subdomain brand abuse
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0168 — Microsoft Live

```text
https://reactivar-microsoft-live.iceiy.com
```

- **Domain:** `reactivar-microsoft-live.iceiy.com`
- **Technique:** Free-hosting (iceiy) Spanish 'reactivar cuenta' account-reactivation lure
- **Detection:** Block *.iceiy.com sign-in lures; watch Spanish 'reactivar/proteccion' Microsoft themes
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0169 — Microsoft

```text
https://microsoftjk.eu.org
```

- **Domain:** `microsoftjk.eu.org`
- **Technique:** Typosquat on free eu.org subdomain
- **Detection:** Flag 'microsoft'+random-suffix labels on eu.org and other free registrars
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0170 — Microsoft

```text
http://microsoft-login-securitylogin.jimdofree.com
```

- **Domain:** `microsoft-login-securitylogin.jimdofree.com`
- **Technique:** Free-hosting (Jimdo) fake login page
- **Detection:** Block *.jimdofree.com hosting 'microsoft-login' keywords
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0171 — Microsoft

```text
https://click5.microsoftsupportcenter.digital
```

- **Domain:** `click5.microsoftsupportcenter.digital`
- **Technique:** Tech-support-themed typosquat (.digital TLD, clickN subdomains)
- **Detection:** Block microsoftsupportcenter.digital; hunt clickN.* enumerated subdomains
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0172 — Microsoft

```text
https://click6.microsoftsupportcenter.digital
```

- **Domain:** `click6.microsoftsupportcenter.digital`
- **Technique:** Tech-support-themed typosquat (.digital TLD, clickN subdomains)
- **Detection:** Block microsoftsupportcenter.digital apex to cover all clickN hosts
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0173 — Microsoft

```text
https://microsoft-se.us
```

- **Domain:** `microsoft-se.us`
- **Technique:** Typosquat brand domain (.us)
- **Detection:** Flag newly-registered 'microsoft-*' apex domains on .us
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0174 — Microsoft

```text
http://microsoft.updata.net.cn
```

- **Domain:** `microsoft.updata.net.cn`
- **Technique:** Subdomain deception ('microsoft' label on attacker apex)
- **Detection:** Alert when 'microsoft' is a subdomain of an unrelated apex domain
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0175 — Microsoft 365

```text
https://microsoft.authorised-support.com/new-account/eozafbyj1bjlmgufsilkjjr9kpvsy5kc3uky=3ag==8vvfbsldlv15mz1rxx1fwz09rtfbnsflls09xslw=/6xx5kg1mkrnjeu3rsnc8diftm7r4v1de
```

- **Domain:** `microsoft.authorised-support.com`
- **Technique:** AiTM kit on authorised-support.com (base64-like token path)
- **Detection:** Block *.authorised-support.com; same kit as login.authorised-support.com
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0176 — Microsoft 365

```text
https://microsoft365businessbasic.com
```

- **Domain:** `microsoft365businessbasic.com`
- **Technique:** Typosquat brand/product domain
- **Detection:** Monitor registrations combining 'microsoft365' with SKU names (businessbasic)
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0177 — Office 365

```text
http://office365licensingsupport.com
```

- **Domain:** `office365licensingsupport.com`
- **Technique:** Typosquat (licensing/support themed brand domain)
- **Detection:** Flag 'office365'+support/licensing keyword apex domains
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0178 — Microsoft 365

```text
https://microsoft365updates.com
```

- **Domain:** `microsoft365updates.com`
- **Technique:** Typosquat (update-themed brand domain)
- **Detection:** Monitor 'microsoft365'+updates/alerts apex registrations
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0179 — Microsoft

```text
https://www-microsoft.com.cn
```

- **Domain:** `www-microsoft.com.cn`
- **Technique:** Typosquat (www-microsoft hyphen trick, .com.cn)
- **Detection:** Flag 'www-microsoft' hyphenated lookalikes across ccTLDs
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0180 — Microsoft SharePoint

```text
https://microsoft-sharepoint.fr
```

- **Domain:** `microsoft-sharepoint.fr`
- **Technique:** Typosquat SharePoint brand domain (.fr)
- **Detection:** Alert on 'microsoft-sharepoint' apex domains and SharePoint doc-share lures
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0181 — Microsoft

```text
https://microsoftuk.co
```

- **Domain:** `microsoftuk.co`
- **Technique:** Typosquat brand domain (.co)
- **Detection:** Flag 'microsoft'+region ('uk') apex domains on non-Microsoft TLDs
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0182 — Microsoft

```text
https://microsoft.vpn-update.org
```

- **Domain:** `microsoft.vpn-update.org`
- **Technique:** Subdomain deception ('microsoft' label on vpn-update.org)
- **Detection:** Alert when 'microsoft' subdomain sits on an unrelated apex
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0183 — Outlook / Office 365

```text
https://outlook-office365.com
```

- **Domain:** `outlook-office365.com`
- **Technique:** Typosquat combining outlook+office365 brand terms
- **Detection:** Flag apex domains concatenating 'outlook' and 'office365'
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0184 — Outlook

```text
https://outlook.webaccess-alert.com/s/63bzgfsvbwsfcdx7y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a
```

- **Domain:** `outlook.webaccess-alert.com`
- **Technique:** AiTM (outlook subdomain, /s/<id>/<uuid> tracked victim path)
- **Detection:** Block *.webaccess-alert.com; hunt /s/<slug>/<hex>/<uuid> AiTM link structure
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0185 — Outlook

```text
https://outlook.verifytoken.com/s/63bzgfsvbwsfcdx7y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a
```

- **Domain:** `outlook.verifytoken.com`
- **Technique:** AiTM (outlook subdomain, same /s/ per-victim token path as webaccess-alert.com)
- **Detection:** Block *.verifytoken.com; correlate identical /s/ path IDs across sibling AiTM domains
- **Source:** phishunt.io (OpenPhish) — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0186 — Office 365

```text
https://office365.rricrosoft-offices.org/i/df3667320560f4a8a9918ef9f3f4c4383
```

- **Domain:** `office365.rricrosoft-offices.org`
- **Technique:** homoglyph typosquat (rn→m 'rricrosoft') with tokenized /i/<32-hex> AiTM tracking path
- **Detection:** Alert on registrable domains where 'microsoft' is spelled with 'rn' (rricrosoft/rnicrosoft) and any host serving a /i/[a-f0-9]{32} path
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0187 — Microsoft 365

```text
http://microsoft365licensingsupport.com
```

- **Domain:** `microsoft365licensingsupport.com`
- **Technique:** brand-impersonation typosquat domain (licensing/tech-support lure)
- **Detection:** Flag newly-registered domains concatenating 'microsoft365' with support/licensing/billing keywords; not owned by Microsoft ASN
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0188 — OneDrive

```text
https://onedrive.at-us.therelayservice.com/matpwp#/main?type=onedrive&locale=en&token=klb1x-bsfowhfwldwy5w5kex8sqynzrdesvfmnxmjl0tdf7uku8us441ssdv8qxwab7r07sx8d2tcaaxbilw7jrzwi1bt5g3m5qzpqncstyknfwj
```

- **Domain:** `onedrive.at-us.therelayservice.com`
- **Technique:** subdomain spoof ('onedrive.*' label on unrelated base domain) with long token and #/ SPA fragment
- **Detection:** Hunt for host labels 'onedrive.'/'login.' prepended to non-Microsoft registrable domains, plus URLs containing '?type=onedrive' behind a # fragment
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0189 — Outlook

```text
http://outlookmail.social
```

- **Domain:** `outlookmail.social`
- **Technique:** brand-keyword typosquat on cheap TLD (.social)
- **Detection:** Match 'outlook'+'mail' registrable domains on low-cost TLDs (.social/.online/.store)
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0190 — Outlook

```text
https://plugins.sugar-outlook.com
```

- **Domain:** `plugins.sugar-outlook.com`
- **Technique:** lookalike domain embedding 'outlook' brand keyword
- **Detection:** Alert on registrable domains containing 'outlook' not delegated to Microsoft (microsoft.com/office.com) NS
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0191 — Microsoft (Hotmail/Live)

```text
https://hotmail143.net
```

- **Domain:** `hotmail143.net`
- **Technique:** typosquat of Hotmail/Live consumer brand (brand+digits)
- **Detection:** Flag 'hotmail'/'live'/'msn' followed by digits on non-Microsoft domains
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0192 — OneDrive / Office 365

```text
http://www.camisasdecolores.net/Office/onedrive-verify-obf.html
```

- **Domain:** `www.camisasdecolores.net`
- **Technique:** compromised legitimate site hosting obfuscated OneDrive 'verify' HTML credential page
- **Detection:** Hunt for '/Office/' paths and filenames like 'onedrive-verify*.html' on otherwise-benign compromised hosts
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0193 — Outlook / Exchange (OWA)

```text
http://www.owaexchange.com/owa/
```

- **Domain:** `www.owaexchange.com`
- **Technique:** lookalike domain serving a fake Outlook Web Access /owa/ login
- **Detection:** Match 'owa'/'exchange' lookalike registrable domains that serve a /owa/ login form
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0194 — Office 365

```text
https://office-365-msn--oficeer.replit.app/
```

- **Domain:** `office-365-msn--oficeer.replit.app`
- **Technique:** typosquat ('oficeer') on free app-hosting platform (replit.app)
- **Detection:** Alert on 'office-365'/'msn' keyworded hostnames on replit.app, vercel.app, workers.dev and similar free hosting
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0195 — Microsoft (Outlook/Hotmail)

```text
https://login.hotmails.info/
```

- **Domain:** `login.hotmails.info`
- **Technique:** Credential-harvesting fake sign-in that proxies a real Microsoft OAuth authorize flow (client_id 4765445b-32c6-49b0-83e6-1d93765276ca) redirecting to office.com/landingv2 to look legitimate
- **Detection:** Alert on 'hotmails.info' (and login./www. subdomains) in proxy/DNS logs; hunt for outbound Microsoft OAuth authorize requests where the host is NOT login.microsoftonline.com but redirect_uri=www.office.com
- **Source:** OpenPhish public feed — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0196 — Microsoft Outlook / Office 365

```text
http://ctia-outlook-2026.s1.yapla.com/en/visitors
```

- **Domain:** `ctia-outlook-2026.s1.yapla.com`
- **Technique:** Outlook-2026-themed credential phishing hosted on abused legitimate SaaS platform (Yapla)
- **Detection:** Flag *.yapla.com paths containing 'outlook'/'2026' brand lures; monitor Yapla visitor pages referrer-mismatched to Outlook login themes
- **Source:** phishunt.io / OpenPhish — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0197 — Microsoft 365 (webmail)

```text
https://servermailprotection-1sfinfomembers.s3.eu-west-1.amazonaws.com/log.html#ssa@microsoft.com
```

- **Domain:** `servermailprotection-1sfinfomembers.s3.eu-west-1.amazonaws.com`
- **Technique:** AWS S3-hosted static credential-harvest page (log.html) with victim email pre-seeded in the URL fragment to auto-populate the fake Microsoft login
- **Detection:** Hunt S3 static-website URLs named 'log.html'/'login.html' with a '#<email>' fragment; block *.s3.*.amazonaws.com pages carrying Microsoft-branded login forms
- **Source:** TweetFeed / @muha2xmad (X) — https://x.com/muha2xmad/status/2098129930017992837
- **Status:** active
- **First seen:** 2026-09-10

### mfs-0198 — Microsoft Entra ID / 365

```text
https://deploypasskey.com/
```

- **Domain:** `deploypasskey.com`
- **Technique:** Help-desk social-engineering into rogue passkey/MFA enrollment (O-UNC-066); per-victim subdomains like <company>.deploypasskey.com
- **Detection:** Alert on newly-registered domains containing 'passkey' with an org-named subdomain; correlate with Entra ID security-info / passkey (FIDO2) registration events from unfamiliar IPs
- **Source:** PurpleSec (O-UNC-066 passkey campaign) — https://purplesec.org/blog/entra-passkey-hijack-o-unc-066/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0199 — Microsoft Entra ID / 365

```text
https://passkeyadd.com/
```

- **Domain:** `passkeyadd.com`
- **Technique:** Rogue passkey-enrollment lure (O-UNC-066); tricks victims into adding an attacker-controlled passkey to their Microsoft account
- **Detection:** Block 'passkey'-themed lookalike domains; monitor Entra ID audit logs for 'Add passkey'/'Register security info' immediately after a suspicious sign-in
- **Source:** PurpleSec (O-UNC-066 passkey campaign) — https://purplesec.org/blog/entra-passkey-hijack-o-unc-066/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0200 — Microsoft 365

```text
http://login-microsoftonnline.jimdofree.com
```

- **Domain:** `login-microsoftonnline.jimdofree.com`
- **Technique:** typosquat (microsoftonnline) on free Jimdo hosting
- **Detection:** Alert on *.jimdofree.com / *.jimdosite.com referencing 'microsoft'/'login'; doubled-letter typos of microsoftonline
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0201 — Microsoft Office 365

```text
https://office.evergreenfin.ltd/
```

- **Domain:** `office.evergreenfin.ltd`
- **Technique:** lookalike 'office' subdomain credential-harvest page
- **Detection:** Flag 'office'/'onelogin' subdomains on unrelated .ltd base domains; newly-registered evergreenfin.ltd
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0202 — Microsoft 365

```text
https://onelogin.evergreenfin.ltd/
```

- **Domain:** `onelogin.evergreenfin.ltd`
- **Technique:** SSO-themed lookalike subdomain on shared phishing infrastructure
- **Detection:** Pivot on evergreenfin.ltd hosting/cert; correlate sibling 'office.' and 'onelogin.' subdomains serving M365 login kit
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-15

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["microsoft-advertising-authentification.sgn-1.com", "emanuelabsoluciones.com", "microsoft-alpha.vercel.app", "watco.microsoft-notifcation.com", "50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document.workers.dev", "aquaclaude-09494-9099403-docviewer.clear90489058903-document.workers.dev", "spx.pamconj.com", "login-microsoft-0nline.ts.r.appspot.com", "login-microsoft-outlook.el.r.appspot.com", "tlook-off365-signin.el.r.appspot.com", "xmaksvwq.wze.io", "noithatviet24h.vn", "newprojectdocument.uc.r.appspot.com", "onedrivelinkedindocument.oa.r.appspot.com", "spherical-door-277805.uc.r.appspot.com", "voicemail365.nn.r.appspot.com", "office365-portal-verify.el.r.appspot.com", "loginblxxslingfbvfgh600ohjm.ga", "notifications.microsoft-ssl.com", "login-outlook365.yzz.me", "grupoimpaktu.ao", "login.authorised-support.com", "bmb.adv.br", "microsoftwordob.blogspot.com", "microsoft0117.vercel.app", "proteccion-outlook2026.iceiy.com", "advancedplacyncement.vu", "amstardmzsmc.vu", "arandasoftzfdware.vu", "avisoretentiunionllc.vu", "capitalflwxinancialpartners.vu", "certififiycationedge.vu", "connectivnqzityltd.vu", "crrbcearegroup.vu", "digitaltrafwwrficsystems.vu", "exceltecbusinessbwpsolutions.vu", "genamewwgdiamarketing.vu", "globaieflsoftinc.vu", "globalmixeucbdmodetechnologyinc.vu", "globalprojectspvtltd.vu", "joinbusinessmanagementconsdjeulting.vu", "kentmanqhfufacturingcompany.vu", "kleepxrnlinecorporation.vu", "knsinternacshtional.vu", "monttmmlrustcompany.vu", "mtprormtductions.vu", "realestatecotblrp.vu", "siottxgroup.vu", "summitcapitaltrapojininggroup.vu", "techcompositnkoes.vu", "techromixsolutionlonsinc.vu", "passkeyhelpdesk.com", "secure-passkey.com", "setupmypasskey.com", "add-passkey.com", "portalsetuphub.com", "odahlzr5lm.reliabilityinoperations.de", "cloudbemismanufacturingcompanygroup.rydezyhrsysteminc.vu", "crsons.net", "afghantarin.com", "cabinetzeukeng.net", "assignpasskey.com", "mfaregister.com", "nowsso.com", "oskeysetup.com", "passkey-mfa.com", "integratedsso.com", "oktasession.com", "keysyncos.com", "oskeysync.com", "indecodesign.net", "jzqs-udkz-yhxx.hutton-aasir-dropons-com-s-account.workers.dev", "cdn.bloom.io", "oskeyregister.com", "syncmykey.com", "myconnectkey.com", "oskeyconnect.com", "validationsetupac.com", "oursso.com", "passkeydeploy.com", "registermymfa.com", "setpasskey.com", "xn--mcrosoftonlne-39bk.com", "microsoftonline-recovery.com", "microsoftonlinecommonoauth.com", "0utl00k.online", "0utl00k.store", "0utl00k.site", "microsoftmultifactor.com", "microsoftauthverify.com", "office365idp.com", "office365mail.com", "microsoft365online.cloud", "https-forms-cloud-microsoft-pages-responsepage-a.link", "onedrive-share.online", "pdf-onedrivesharedfile.work", "microsoftteamsbooking.com", "microsoftteambookingz.top", "microsofteams.live", "outlook365allservers.help", "support-outlook.com", "contactsupport-microsoft.com", "helpsecure-microsoft.com", "microsoft251207.com", "676132-microsoft.com", "outlook10.net", "outlo0k.com", "onedrivee.online", "office365.internal-alerts.com", "support.m365-microsoft.com", "security.email-microsoft.com", "programme-hup.m365-microsoft.com", "security.m365-microsoft.com", "emailnotifications.m365-microsoft.com", "reactivar-microsoft-live.iceiy.com", "microsoftjk.eu.org", "microsoft-login-securitylogin.jimdofree.com", "click5.microsoftsupportcenter.digital", "click6.microsoftsupportcenter.digital", "microsoft-se.us", "microsoft.updata.net.cn", "microsoft.authorised-support.com", "microsoft365businessbasic.com", "office365licensingsupport.com", "microsoft365updates.com", "www-microsoft.com.cn", "microsoft-sharepoint.fr", "microsoftuk.co", "microsoft.vpn-update.org", "outlook-office365.com", "outlook.webaccess-alert.com", "outlook.verifytoken.com", "office365.rricrosoft-offices.org", "microsoft365licensingsupport.com", "onedrive.at-us.therelayservice.com", "outlookmail.social", "plugins.sugar-outlook.com", "hotmail143.net", "www.camisasdecolores.net", "www.owaexchange.com", "office-365-msn--oficeer.replit.app", "login.hotmails.info", "ctia-outlook-2026.s1.yapla.com", "servermailprotection-1sfinfomembers.s3.eu-west-1.amazonaws.com", "deploypasskey.com", "passkeyadd.com", "login-microsoftonnline.jimdofree.com", "office.evergreenfin.ltd", "onelogin.evergreenfin.ltd"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

