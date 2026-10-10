# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 328
- **Retention:** rolling 30 days
- **Last updated:** 2026-10-10
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
| mfs-0001 | Microsoft Advertising / Microsoft account | typosquat lookalike FQDN impersonating a Microsoft sign-in page (brand keywords + 'authentification' stuffed into a non-Microsoft host) | 2026-09-11 | OpenPhish (public feed) |
| mfs-0002 | Microsoft Entra ID / Azure AD | credential-phish on a compromised legitimate domain that replays the genuine AADSTS50058 error string to mimic a real Azure AD silent-auth redirect | 2026-09-11 | OpenPhish (public feed) |
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
| mfs-0027 | Microsoft Outlook | typosquat credential-harvest landing page ('proteccion-outlook2026') | 2026-09-13 | OpenPhish (via phishunt.io) |
| mfs-0056 | Microsoft Entra ID | IT-help-desk vishing + passkey-enrollment AiTM (O-UNC-066 'Pink') | 2026-09-11 | The Hacker News |
| mfs-0057 | Microsoft Entra ID | Passkey-themed AiTM phishing mimicking Microsoft sign-in via SMS lures | 2026-09-11 | The Hacker News |
| mfs-0058 | Microsoft 365 | Passkey-enrollment phishing directing users to counterfeit Microsoft sign-in | 2026-09-11 | The Hacker News |
| mfs-0059 | Microsoft Entra ID | Fake passkey-setup portal harvesting Microsoft creds/session | 2026-09-11 | The Hacker News |
| mfs-0060 | Microsoft 365 | Counterfeit Microsoft portal-setup page in passkey/SSO vishing campaign | 2026-09-11 | The Hacker News |
| mfs-0137 | Microsoft 365 (login.microsoftonline.com) | typosquat / brand-plus-keyword ('recovery') credential-reset lure | 2026-09-12 | phishunt.io |
| mfs-0139 | Microsoft Outlook | leetspeak typosquat (zero-for-o) of outlook.com | 2026-09-11 | phishunt.io |
| mfs-0140 | Microsoft Outlook | leetspeak typosquat of outlook on cheap .store TLD | 2026-09-11 | phishunt.io |
| mfs-0141 | Microsoft Outlook | leetspeak typosquat of outlook on .site TLD | 2026-09-11 | phishunt.io |
| mfs-0145 | Microsoft 365 / Outlook Web mail | typosquat Office365 webmail sign-in lure | 2026-09-11 | phishunt.io |
| mfs-0146 | Microsoft 365 | typosquat brand-stuffed domain on .cloud TLD | 2026-09-12 | phishunt.io |
| mfs-0147 | Microsoft Forms | deceptive-subdomain typosquat mimicking a forms.microsoft.com response-page URL ('https-' prefix to fake the scheme) | 2026-09-12 | phishunt.io |
| mfs-0148 | Microsoft OneDrive | typosquat OneDrive shared-document credential lure | 2026-09-11 | phishunt.io |
| mfs-0155 | Microsoft support | typosquat tech-support-scam / credential lure | 2026-09-11 | phishunt.io |
| mfs-0156 | Microsoft support | typosquat 'secure help' credential/tech-support lure | 2026-09-11 | phishunt.io |
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
| mfs-0198 | Microsoft Entra ID / 365 | Help-desk social-engineering into rogue passkey/MFA enrollment (O-UNC-066); per-victim subdomains like <company>.deploypasskey.com | 2026-09-15 | PurpleSec (O-UNC-066 passkey campaign) |
| mfs-0199 | Microsoft Entra ID / 365 | Rogue passkey-enrollment lure (O-UNC-066); tricks victims into adding an attacker-controlled passkey to their Microsoft account | 2026-09-15 | PurpleSec (O-UNC-066 passkey campaign) |
| mfs-0200 | Microsoft 365 | typosquat (microsoftonnline) on free Jimdo hosting | 2026-09-15 | OpenPhish |
| mfs-0201 | Microsoft Office 365 | lookalike 'office' subdomain credential-harvest page | 2026-09-15 | OpenPhish |
| mfs-0202 | Microsoft 365 | SSO-themed lookalike subdomain on shared phishing infrastructure | 2026-09-15 | OpenPhish |
| mfs-0203 | Microsoft Teams | typosquat brand-impersonation Teams invite lure | 2026-09-16 | OpenPhish |
| mfs-0204 | Microsoft Teams | typosquat brand-impersonation Teams invite lure | 2026-09-16 | OpenPhish |
| mfs-0205 | Microsoft Teams | typosquat brand-impersonation Teams invite lure | 2026-09-16 | OpenPhish |
| mfs-0206 | Azure AD / Entra ID | AiTM credential-harvest landing spoofing Azure AD error | 2026-09-16 | OpenPhish |
| mfs-0207 | Microsoft Outlook | Outlook credential phish on dynamic-DNS (duckdns) host | 2026-09-16 | OpenPhish |
| mfs-0208 | Microsoft Outlook | Outlook credential phish on dynamic-DNS (duckdns) host | 2026-09-16 | OpenPhish |
| mfs-0224 | Microsoft Teams | typosquat / brand-impersonation domain (Teams installer lure) | 2026-09-15 | phishunt.io |
| mfs-0225 | Microsoft OneDrive | typosquat on cheap .cfd TLD (OneDrive document-share lure) | 2026-09-15 | phishunt.io |
| mfs-0226 | Microsoft Teams | typosquat (transposed 'steam'/'teams') | 2026-09-15 | phishunt.io |
| mfs-0227 | Microsoft 365 | typosquat brand-impersonation domain on .sbs TLD | 2026-09-15 | phishunt.io |
| mfs-0228 | Microsoft 365 | tech-support themed brand impersonation | 2026-09-15 | phishunt.io |
| mfs-0229 | Microsoft | tech-support / help-desk themed brand impersonation | 2026-09-15 | phishunt.io |
| mfs-0230 | Microsoft | homoglyph typosquat (zero-for-o in 'micros0ft') | 2026-09-15 | phishunt.io |
| mfs-0231 | Microsoft | typosquat brand-impersonation on .info TLD | 2026-09-15 | phishunt.io |
| mfs-0232 | Microsoft Outlook | typosquat pairing 'outlook' with unrelated keyword | 2026-09-15 | phishunt.io |
| mfs-0233 | Microsoft Outlook | typosquat brand-impersonation domain | 2026-09-14 | phishunt.io |
| mfs-0234 | Microsoft Outlook | typosquat on commerce .shop TLD | 2026-09-14 | phishunt.io |
| mfs-0235 | Microsoft Outlook | typosquat brand-impersonation domain | 2026-09-14 | phishunt.io |
| mfs-0236 | Microsoft Teams | typosquat on abused .top TLD | 2026-09-14 | phishunt.io |
| mfs-0237 | Microsoft 365 | typosquat of 'microsoftonline' (dropped char) on .site TLD | 2026-09-14 | phishunt.io |
| mfs-0238 | Microsoft | long-string 'AI/investment' themed brand-impersonation lure | 2026-09-14 | phishunt.io |
| mfs-0239 | Microsoft OneDrive | deceptive subdomain-ordering typosquat ('com-onedrive-microsoftonline') | 2026-09-14 | phishunt.io |
| mfs-0244 | Microsoft 365 | AiTM (Evilginx2) reverse-proxy credential/session-cookie theft — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0245 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0246 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0247 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0248 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0249 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0250 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0251 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0252 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0253 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0254 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0255 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0256 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0257 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0258 | Microsoft 365 | AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS | 2026-09-11 | CloudSEK TRIAD |
| mfs-0259 | Microsoft 365 / Entra ID | Credential-harvest kit hosted on abused Replit app hosting; page title cloned from the Entra ID 'Sign in to your account' screen | 2026-09-14 | PhishStats |
| mfs-0260 | Microsoft 365 / Entra ID | Same Replit-hosted credential-harvest kit; title 'Sign in to your account' | 2026-09-14 | PhishStats |
| mfs-0268 | Microsoft Teams | Dedicated typosquat domain (teams-login[.]com) serving per-victim tokenized landing pages under /page/<random>/ | 2026-09-17 | OpenPhish |
| mfs-0269 | Microsoft Outlook | Free-hosting (hstn.me / Hostinger free tier) Outlook lure with ?i=1 stage parameter, same kit family as the already-tracked iceiy.com/hstn.me Spanish-language Outlook lures | 2026-09-17 | Phishunt.io |
| mfs-0270 | Microsoft OneDrive / Microsoft 365 | Compromised Brazilian consultancy site serving the obfuscated 'onedrive-verify-obf.html' kit — same file name as the already-tracked grupoimpaktu.ao and camisasdecolores.net instances | 2026-09-17 | Phishunt.io |
| mfs-0272 | Microsoft 365 / Office | Lookalike 'offices-support' domain with a Spanish 'soporte' subdomain; uses the same /i/<hash> landing path as the m365-microsoft.com and internal-alerts.com kits | 2026-09-18 | OpenPhish |
| mfs-0273 | Microsoft 365 / Office | Credential-capture form on a lookalike Office support domain; a second step of the same /i/<hash> kit | 2026-09-18 | OpenPhish |
| mfs-0274 | Microsoft 365 / Office | Lookalike combo-squat domain (office-share-microsoft) with a victim-name subdomain serving a fake Microsoft sign-in page | 2026-09-18 | OpenPhish |
| mfs-0275 | Microsoft Office 365 | Office credential-phishing page hosted under an /office path on a compromised or unrelated site | 2026-09-18 | OpenPhish |
| mfs-0276 | Microsoft 365 | Typosquat m365-microsoft.com phishing platform; /page/<32-hex>/<32-hex> landing variant of the /i/ link we already track | 2026-09-18 | OpenPhish |
| mfs-0277 | Microsoft 365 / Entra ID | GhostCode device-code phishing (OAuth device authorization grant abusing the Microsoft Authentication Broker), delivered via a password-protected HTML file on WeTransfer | 2026-09-15 | eSentire |
| mfs-0278 | Microsoft 365 / Entra ID | GhostCode relay and bot-filtering layer that redirects to the device-code phishing page via /scanna/<32-hex>/<64-hex> paths | 2026-09-15 | eSentire |
| mfs-0279 | Microsoft 365 | Spanish-language 'Verificacion Microsoft' credential harvester on free hosting (freepage.cc) | 2026-09-18 | OpenPhish |
| mfs-0280 | Microsoft 365 | Fake 'Microsoft Security - Verify Your Identity' page hosted on Linode Object Storage | 2026-09-18 | OpenPhish |
| mfs-0290 | Microsoft 365 / Entra ID | Typosquat of login.microsoftonline.com on a .pl ccTLD, hosting a fake account-login lure | 2026-09-16 | PhishDestroy |
| mfs-0291 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0292 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0293 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0294 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0295 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0296 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0297 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0298 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0299 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0300 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0301 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0302 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0303 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0304 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0305 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0306 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0307 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0308 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0309 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0310 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0311 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0312 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0313 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0314 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0315 | Microsoft 365 / Entra ID | GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT | 2026-09-15 | eSentire |
| mfs-0316 | Microsoft 365 / Entra ID | GhostCode relay / decoy PDF host that redirects to the device-code phishing kit | 2026-09-15 | eSentire |
| mfs-0317 | Microsoft 365 | Lookalike domain on the .ms ccTLD posing as a Microsoft authentication short link | 2026-09-18 | OpenPhish |
| mfs-0318 | Microsoft | Fake support domain with a per-victim encoded token in the /login/ path | 2026-09-18 | OpenPhish |
| mfs-0319 | Microsoft | Fake support domain with a shorter per-victim token in the /login/ path | 2026-09-18 | OpenPhish |
| mfs-0343 | Microsoft 365 | GhostCode kit: password-protected HTML attachment leads to a bot-filtering relay, then Microsoft device-code phishing via the Authentication Broker | 2026-09-16 | eSentire via Cyber Security News |
| mfs-0344 | Microsoft 365 | Fake Microsoft sign-in page hosted on Linode (Akamai) Object Storage bucket, like the earlier mxoff linodeobjects.com lure | 2026-09-18 | OpenPhish |
| mfs-0349 | Microsoft 365 | GhostCode device-code phishing: flipbook relay with bot filtering, reached from a password-protected HTML attachment in WeTransfer, redirects to a fake account-access sign-in page | 2026-09-15 | eSentire TRU |
| mfs-0350 | Microsoft Outlook | Free-site-builder phishing (Weebly) with a French-language 'connect to Microsoft Outlook' credential lure | 2026-09-21 | OpenPhish |
| mfs-0351 | Microsoft 365 / Outlook | AiTM short-token lure (same /E.<token> path pattern as the authentication.ms kit) disguised as a 'microsoftonline mailbox upgrade' | 2026-09-22 | OpenPhish |
| mfs-0352 | Microsoft 365 | AiTM MFA lure: a fake 'multi-factor' domain using the /E.<token> kit pattern with ContextID=O365 | 2026-09-22 | OpenPhish |
| mfs-0353 | Microsoft 365 | AiTM MFA lure: a second token on the same multi-factor.link kit infrastructure | 2026-09-22 | OpenPhish |
| mfs-0354 | Microsoft Teams / Microsoft 365 | AiTM lookalike .ms domain with a Teams collaboration lure aimed at a specific tenant (iberdrola.es) | 2026-09-22 | OpenPhish |
| mfs-0355 | Microsoft 365 | Typosquat domain that tracks each victim with a ?rid= campaign ID (GoPhish-style) | 2026-09-22 | OpenPhish |
| mfs-0356 | Microsoft OneDrive / Microsoft 365 | Credential page hosted on Cloudflare Workers, with a subdomain that mimics '365 mso drive auth' | 2026-09-22 | OpenPhish |
| mfs-0357 | Microsoft 365 | Punycode homoglyph 'konto' subdomain on known Microsoft phishing infrastructure (evergreenfin.ltd) | 2026-09-22 | OpenPhish |
| mfs-0358 | Microsoft Teams | Teams-lookalike domain serving a tokenized /p/<id>/<id>/ redirect to a credential page | 2026-09-22 | OpenPhish |
| mfs-0359 | Microsoft 365 | Free-hosting phish (GitHub Pages) with a Microsoft-branded path posing as a sign-in page | 2026-09-22 | OpenPhish |
| mfs-0360 | Microsoft 365 (Excel) | Fake 'Microsoft Excel 2026 Document Access' page that collects email and password, hosted on the Craftum site builder | 2026-09-22 | PhishStats |
| mfs-0361 | Outlook Web App | Clone of an OWA/Exchange login page ('BNI Outlook') on Vercel free hosting, targeting one organisation's webmail | 2026-09-20 | PhishStats |
| mfs-0362 | Microsoft 365 | Microsoft 'Enter password / sign in timed-out' clone on Replit; same template as the existing security-server-page campaign | 2026-09-20 | PhishStats |
| mfs-0363 | Microsoft 365 | Microsoft 'Enter password / sign in timed-out' clone on Replit; same template as the existing security-server-page campaign | 2026-09-20 | PhishStats |
| mfs-0364 | Microsoft 365 | Microsoft sign-in clone ('To access document, you'll need to verify your account') on a lookalike or compromised domain | 2026-09-17 | PhishStats |
| mfs-0365 | Microsoft 365 | Fake 'Document Access Verification' page with Microsoft Corporation branding that asks for an email address; path is personalised to the victim | 2026-09-15 | PhishStats |
| mfs-0366 | Microsoft account (Outlook/Hotmail) | Spanish-language fake 'Microsoft Services Agreement updated' page on Replit; same kit as office-365-msn--oficeer.replit.app | 2026-09-15 | PhishStats |
| mfs-0367 | Microsoft OneDrive / Office 365 | 'Proof Of Payment' OneDrive lure hosted on GitHub Pages that asks for the victim's Microsoft email | 2026-09-14 | PhishStats |
| mfs-0368 | Microsoft account / Outlook | Fake 'Security verification - Microsoft account' credential-harvest page on a free Replit app subdomain (security-server-page-- template) | 2026-09-22 | OpenPhish |
| mfs-0369 | Microsoft account / Outlook | Same Replit 'security-server-landing-page--' Microsoft account verification template seen in earlier replit.app lures | 2026-09-22 | OpenPhish |
| mfs-0370 | Microsoft 365 | Brand typosquat (Röchling) on a 4-day-old Cloudflare-fronted domain hosting a cloned Entra ID sign-in page | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0371 | Microsoft 365 | Free-hosting abuse (Replit) using the 'security-server-landing-page--<user>' AiTM lure series | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0372 | Microsoft account | Replit-hosted fake 'Security verification - Microsoft account' page | 2026-09-19 | OpenPhish / PhishTank (via urlscan.io) |
| mfs-0373 | Microsoft 365 | Replit-hosted cloned Entra ID sign-in page (same kit series as known replit.app entries) | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0374 | Microsoft account | Replit-hosted fake Microsoft security verification page | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0375 | Microsoft 365 | Replit-hosted Microsoft sign-in clone | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0376 | Microsoft 365 | Replit-hosted Microsoft sign-in clone | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0377 | Microsoft 365 | Replit-hosted sign-in clone reached through the '?naps' lure parameter | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0378 | Microsoft 365 | Replit-hosted Microsoft sign-in clone | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0379 | Microsoft account | Replit-hosted fake Microsoft security verification page | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0380 | Microsoft account | Replit-hosted fake Microsoft security verification page | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0381 | Microsoft account | DocuSign-themed lure leading to a fake Microsoft security verification page on Replit | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0382 | Microsoft account | DocuSign document lure that harvests Microsoft credentials on Replit | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0383 | Microsoft account | Replit-hosted 'Sign in to your Microsoft account' clone | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0384 | Outlook Web App | Fake Exchange/OWA page on Replit, reached through the tracking redirect user.mxredwood.com | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0385 | Outlook | 'Continue to Outlook' credential page on Replit | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0386 | Microsoft account | Laravel Cloud free-hosting abuse serving a fake Microsoft security verification page | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0387 | Microsoft account | Laravel Cloud 'fls-<uuid>' file-hosting abuse (same pattern as the known hotmail inbox page) | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0388 | Hotmail / Microsoft account | Contabo object-storage bucket hosting a Hotmail credential page | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0389 | Microsoft 365 | Contabo object-storage bucket hosting a Microsoft sign-in clone | 2026-09-19 | OpenPhish (via urlscan.io) |
| mfs-0390 | Hotmail / Microsoft account | Gcore object-storage bucket hosting a fake Microsoft security verification page | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0391 | Hotmail / Microsoft account | Microsoft verification clone on a 15-day-old domain | 2026-09-19 | OpenPhish (via urlscan.io) |
| mfs-0392 | Microsoft account | Compromised site hosting a fake Microsoft security verification page (also served on the kkms. subdomain) | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0393 | Microsoft account | Subdomain on a compromised site serving a Microsoft verification phish | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0394 | Microsoft account | Fake 'project drawings' document lure in a WordPress-like path leading to Microsoft verification | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0395 | Microsoft 365 | Sign-in clone behind a random-hex HTML path per victim; the page 404s after first use | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0396 | Microsoft 365 | Same random-hex HTML path kit as channelhub.online | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0397 | Outlook / Exchange | Compromised site hosting a fake Exchange/Outlook portal | 2026-09-21 | OpenPhish (via urlscan.io) |
| mfs-0398 | Microsoft / Hotmail | KYC-compliance email lure leading to a 'Microsoft | Login' page (mirrored on the hotspot. subdomain) | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0399 | Outlook | Outlook login clone on a lookalike subdomain of a .site domain | 2026-09-20 | OpenPhish (via urlscan.io) |
| mfs-0400 | Microsoft OneDrive | Cloudflare Workers lure: 'Microsoft User shared a document with you' | 2026-09-19 | OpenPhish (via urlscan.io) |
| mfs-0401 | Microsoft OneDrive | Chain of Cloudflare Workers redirects ending on a fake OneDrive page | 2026-09-21 | OpenPhish (via urlscan.io) |
| mfs-0402 | Microsoft OneDrive | Vercel-hosted 'My Files - OneDrive' credential lure | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0403 | Office / OWA | GitHub Pages 'Office Web Access' credential page | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0404 | Outlook | Webflow-hosted 'Outlook Self Service Portal' reached through the shortener alturl.com/acaqd | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0405 | Microsoft OneDrive | Compromised site hosting a per-victim OneDrive 'Access your file' lure (same host as a known entry) | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0406 | Microsoft OneDrive | Personalized OneDrive file-access lure named after the victim | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0407 | Microsoft Entra ID | Fake IT-helpdesk domain serving a 'Microsoft SSO Sign In' page with per-victim GUID tokens | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0408 | Microsoft account | Randomized 'msslogin' subdomain on a generic portal-login domain | 2026-09-16 | OpenPhish (via urlscan.io) |
| mfs-0409 | Microsoft account | Numeric-domain 'Microsoft Login' page with a GUID tracking path | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0410 | Microsoft account | Background-check lure leading to a 'Microsoft Login Page' | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0411 | Microsoft 365 (AXA lure) | Brand-lookalike domain using the /i/<hash> kit also seen on m365-microsoft.com and offices-support.com | 2026-09-19 | OpenPhish (via urlscan.io) |
| mfs-0412 | Microsoft account (ES) | Spanish 'Verificacion Microsoft' page on iceiy.com free hosting, spread via the shortener i.gal/8OhE3 | 2026-09-18 | OpenPhish (via urlscan.io) |
| mfs-0413 | Microsoft account (ES) | Spanish-language Microsoft verification phish on freepage.cc | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0414 | Microsoft account (ES) | goo.su shortener redirecting to renovacion365.zya.me ('Verificacion Microsoft') | 2026-09-19 | OpenPhish (via urlscan.io) |
| mfs-0415 | Microsoft account (ES) | 'Iniciar sesión en tu cuenta Microsoft' clone on yzz.me free hosting | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0416 | Microsoft account (ES) | Spanish Microsoft sign-in clone on alc.onl | 2026-09-17 | OpenPhish (via urlscan.io) |
| mfs-0417 | Microsoft account | Same /E.<token> infrastructure as authentication.ms and multi-factor.link; a sibling URL decodes to a Hoxhunt simulation string, so this may be training infrastructure | 2026-09-22 | OpenPhish (via urlscan.io) |
| mfs-0418 | Microsoft account (E.ON lure) | /E.<token> kit on an E.ON-lookalike domain; possibly phishing-simulation infrastructure | 2026-09-21 | OpenPhish (via urlscan.io) |
| mfs-0419 | Microsoft SharePoint | Typosquat domain ae-sharepoint.com with per-target company subdomains ('Sharepoint Secure Panel'), 0 days old | 2026-09-22 | urlscan.io certstream-suspicious |
| mfs-0420 | Microsoft SharePoint | Per-target subdomain that redirects to sharepointdocument-verification.com ('SharePoint — Documents') | 2026-09-22 | urlscan.io certstream-suspicious |
| mfs-0421 | Microsoft 365 | 0-day-old domain serving a cloned Entra ID 'Sign in to your account' page at /auth | 2026-09-21 | urlscan.io |
| mfs-0422 | Microsoft 365 | 0-day-old typo domain ('gruop') hosting a Microsoft sign-in clone | 2026-09-21 | urlscan.io |
| mfs-0423 | Microsoft 365 | Document-viewer themed 0-day domain serving a Microsoft sign-in clone | 2026-09-19 | urlscan.io |
| mfs-0424 | Microsoft 365 | 0-day .top domain hosting a Microsoft sign-in clone | 2026-09-17 | urlscan.io |
| mfs-0425 | Outlook / Microsoft 365 | Credential-harvest page hosted on Backblaze B2 cloud storage (abuse of trusted cloud storage) | 2026-09-22 | OpenPhish |
| mfs-0426 | Microsoft 365 / Entra ID | Cloned 'Sign in to your account' AAD page on GitHub Pages, loads aadcdn assets | 2026-09-22 | OpenPhish |
| mfs-0427 | Outlook Web App | OWA login clone on a compromised or lookalike 'owa.' subdomain | 2026-09-22 | OpenPhish |
| mfs-0428 | Microsoft 365 | Replit-hosted 'security-server-landing-page' kit cloning the Microsoft sign-in page | 2026-09-22 | OpenPhish |
| mfs-0429 | Microsoft 365 / Outlook | Base64 + nested unescape-obfuscated 'Microsoft | Login' page on Gcore object storage | 2026-09-22 | OpenPhish |
| mfs-0430 | Microsoft Teams / Microsoft 365 | Teams-lookalike domain using the same /p/fjbd-cbch/ path kit as teams-ra.com | 2026-09-22 | OpenPhish |
| mfs-0431 | Microsoft Teams / Microsoft 365 | Teams-lookalike typosquat domain from the same /p/fjbd-* campaign | 2026-09-22 | OpenPhish |
| mfs-0432 | Microsoft 365 | Lookalike '365' domain hosting a cloned Microsoft 'Sign in to your account' account-picker page | 2026-09-22 | OpenPhish |
| mfs-0433 | Microsoft 365 / Outlook | Microsoft login clone on Replit free hosting, part of the recurring 'security-server-landing-page--<user>' kit | 2026-09-22 | OpenPhish |
| mfs-0434 | Microsoft Account | Compromised .cl website hosting a static HTML 'Security verification - Microsoft account' credential page | 2026-09-22 | OpenPhish |
| mfs-0435 | Microsoft Account (DocuSign lure) | Phishing page on an AWS S3 bucket using a DocuSign-themed file name to lead to Microsoft account verification | 2026-09-22 | OpenPhish |
| mfs-0436 | Hotmail / Microsoft 365 | Hotmail account-security update lure hosted on an AWS S3 bucket | 2026-09-22 | OpenPhish |
| mfs-0437 | Microsoft Office 365 | Office 365 login page on Backblaze B2 storage, the same 'myoffice.html' kit as the jamunaban bucket | 2026-09-22 | OpenPhish |
| mfs-0438 | Microsoft Excel / Office 365 | Fake 'Excel - Shared Document' credential page on Cloudflare Workers | 2026-09-22 | OpenPhish |
| mfs-0439 | Microsoft 365 / Entra ID | Credential harvester on a compromised legitimate host, faking an OAuth authorize request with a capital-I 'redirect_urI' parameter pointing at login.microsoftonline.com | 2026-09-25 | OpenPhish + PhishTank (via phishunt.io) |
| mfs-0440 | Microsoft Outlook / Live | Spanish-language 'validar mi cuenta' Outlook account-verification typosquat hosted on the free yzz.me subdomain service over plain HTTP | 2026-09-24 | OpenPhish (via phishunt.io) |
| mfs-0441 | Microsoft 365 | Brandjacked .ms domain masquerading as a Microsoft authentication endpoint; per-victim 'E.<token>' path serves an MFA/confirm-identity credential prompt | 2026-09-25 | OpenPhish public feed |
| mfs-0442 | Microsoft Outlook / Office 365 | Outlook 'notification' credential page on Tencent EdgeOne Pages free hosting, using a long keyword-stuffed label plus random suffix to defeat string blocklists | 2026-09-25 | OpenPhish public feed |
| mfs-0443 | Microsoft 365 | Replit-hosted 'security server' fake sign-in kit; the --<operator> suffix is the attacker's Replit account name, so each actor mass-produces near-identical pages | 2026-09-25 | OpenPhish public feed |
| mfs-0444 | Microsoft 365 | Same Replit 'security-server' Microsoft sign-in kit under a different operator handle | 2026-09-25 | OpenPhish public feed |
| mfs-0445 | Microsoft 365 | Replit 'security-server-page' variant of the same Microsoft credential-harvest kit | 2026-09-25 | OpenPhish public feed |
| mfs-0446 | Microsoft 365 | Free-hosting abuse — credential-harvest page on attacker-created Vercel subdomain; page title is literally "Microsoft" | 2026-09-28 | OpenPhish / phishunt.io |
| mfs-0447 | Microsoft OneDrive | Compromised legitimate site hosting the reused 'onedrive-verify-obf' obfuscated HTML credential kit | 2026-09-28 | OpenPhish / phishunt.io |
| mfs-0448 | Microsoft 365 / Outlook Web | Subdomain squatting on a compromised German domain; label is misspelled 'clovd-micrsotf-mail' plus random hex padding | 2026-09-28 | OpenPhish / phishunt.io |
| mfs-0449 | Microsoft 365 (login.microsoftonline.com) | Typosquat of 'microsoftonline' with an inserted hyphen on a .gr ccTLD | 2026-09-28 | OpenPhish / phishunt.io |
| mfs-0450 | Microsoft Office 365 | Brand-concatenation typosquat ('microsoftoffice' + 'o365') used as a sign-in lure domain | 2026-09-28 | OpenPhish / phishunt.io |
| mfs-0451 | Microsoft Teams | Homoglyph/typosquat ('miccrossofteam' = Microsoft Teams) on a cheap .top TLD, served over plain HTTP | 2026-09-28 | OpenPhish |
| mfs-0452 | Microsoft Outlook / Live | Weebly free-site abuse with a French-language lure ('connexion compte Outlook' = Outlook account sign-in) | 2026-09-28 | OpenPhish |
| mfs-0453 | Microsoft 365 / Outlook | Spanish-language 'verify your account' credential-harvest page on free zya.me subdomain host, homoglyph 'micros0ft' | 2026-09-29 | OpenPhish (via phishunt.io) |
| mfs-0454 | Microsoft 365 | Typosquat brand-in-domain-label credential page behind Cloudflare; flagged young domain | 2026-09-28 | Google Safe Browsing (via phishunt.io) |
| mfs-0455 | Microsoft Teams | Typosquat of 'microsoft teams' (dropped space/letter shuffle) serving fake Teams/M365 sign-in | 2026-09-25 | OpenPhish (via phishunt.io) |
| mfs-0456 | Microsoft Forms / Microsoft 365 | Microsoft Forms-themed lure domain redirecting to cloned Entra ID sign-in | 2026-09-25 | Google Safe Browsing (via phishunt.io) |
| mfs-0457 | Microsoft Teams | Fake 'Teams setup/installer' page pivoting to M365 credential prompt | 2026-09-24 | OpenPhish (via phishunt.io) |
| mfs-0459 | Microsoft 365 / Entra ID | Typosquat sign-in-verification lure, newly registered lookalike | 2026-09-28 | phishunt.io (CT logs) |
| mfs-0460 | Microsoft Account / Live | Typosquat of account.live.com using .live TLD as the brand suffix | 2026-09-28 | phishunt.io (CT logs) |
| mfs-0461 | Microsoft 365 / passkey | Passkey/security-key registration lure — same theme as the Storm-3121/Storm-3032 passkey cluster | 2026-09-28 | phishunt.io (CT logs) |
| mfs-0462 | Microsoft 365 / Office 365 | Brand-plus-suffix typosquat landing page for OWA credential capture | 2026-09-28 | phishunt.io (CT logs) |
| mfs-0463 | Microsoft Teams | Fake Teams meeting-invite lure leading to M365 sign-in page (same pattern as msteamsinvitees.com) | 2026-09-28 | phishunt.io (CT logs) |
| mfs-0464 | Hotmail / Outlook | Hotmail typosquat on cheap .site TLD | 2026-09-28 | phishunt.io (CT logs) |
| mfs-0465 | Outlook / Microsoft 365 | 'New message in your inbox' notification lure to fake OWA logon | 2026-09-27 | phishunt.io (CT logs) |
| mfs-0466 | Microsoft Teams | Teams invite typosquat, sibling of microsofteamsinvite.top on the same registration burst | 2026-09-27 | phishunt.io (CT logs) |
| mfs-0467 | Microsoft Teams | Pluralized-brand typosquat ('microsofts') fake Teams meeting join page | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0468 | Microsoft Teams | Fake Teams download page (variant of the known teams-microsoft-download.com) | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0469 | Outlook | Bare-brand squat on a low-reputation TLD used for webmail credential pages | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0470 | OneDrive / SharePoint | Fake 'shared document' OneDrive lure fronting an M365 sign-in prompt | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0471 | OneDrive | OneDrive brand-plus-suffix squat registered in the same batch as onedriveshare.net | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0472 | Microsoft / Windows | Tech-support-themed lure escalating to Microsoft account sign-in | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0473 | OneDrive / Microsoft 365 | Hyphenated brand-pair typosquat hosting a OneDrive document-access sign-in | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0474 | Outlook / Microsoft 365 | Mailbox-notification lure domain for OWA credential capture | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0475 | OneDrive | Homoglyph typosquat (zero-for-O) OneDrive file-share phishing page | 2026-09-26 | phishunt.io (CT logs) |
| mfs-0476 | Microsoft 365 | Fake Microsoft sales/support contact page routing to an Entra ID credential prompt | 2026-09-25 | phishunt.io (CT logs) |
| mfs-0477 | Outlook / Microsoft Defender | 'Protect your mailbox' security-alert lure to fake Outlook sign-in | 2026-09-25 | phishunt.io (CT logs) |
| mfs-0478 | Outlook Web Access | Fake OWA 'access portal' credential-harvest page | 2026-09-25 | phishunt.io (CT logs) |
| mfs-0479 | OneDrive | Reversed-label squat designed to read as 'onedrive.com' in truncated mobile URL bars | 2026-09-25 | phishunt.io (CT logs) |
| mfs-0480 | Outlook / Microsoft Account | Account-recovery lure harvesting credentials plus recovery email/phone for MFA reset | 2026-09-24 | phishunt.io (CT logs) |
| mfs-0481 | Microsoft 365 / Entra ID | Direct login-page typosquat (m365 + login + microsoft tokens) | 2026-09-24 | phishunt.io (CT logs) |
| mfs-0482 | Microsoft 365 / Entra ID | Security-alert lure domain for MFA/passkey re-enrollment social engineering | 2026-09-24 | phishunt.io (CT logs) |
| mfs-0483 | OneDrive / SharePoint | Combined OneDrive+SharePoint squat mimicking the real *-my.sharepoint.com personal-site hostname | 2026-09-24 | phishunt.io (CT logs) |
| mfs-0484 | Microsoft 365 / Entra ID | Near-exact typosquat of login.microsoftonline.com with 'my' prefix | 2026-09-23 | phishunt.io (CT logs) |
| mfs-0485 | Microsoft 365 / OneDrive | Abbreviation squat (ms365) hosting OneDrive document-share credential page | 2026-09-23 | phishunt.io (CT logs) |
| mfs-0486 | Microsoft 365 / Outlook | Homoglyph (micr0s0ft) mail-setup lure, long multi-token domain to defeat substring rules | 2026-09-23 | phishunt.io (CT logs) |
| mfs-0487 | Microsoft 365 | Fake 'My Account' portal squat of myaccount.microsoft.com | 2026-09-22 | phishunt.io (CT logs) |
| mfs-0488 | Microsoft Outlook / Microsoft 365 | Subdomain of an active phishing estate (evergreenfin.ltd) serving a fake Outlook/OWA sign-in page | 2026-09-29 | OpenPhish (via phishunt.io) |
| mfs-0489 | Microsoft 365 / Office 365 | Homoglyph typosquat (zero-for-o) of 'microsoftoffice365' hosting a credential-harvest sign-in clone | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0490 | Microsoft Entra ID / login.microsoftonline.com | Typosquat of login.microsoftonline.com on a low-cost .top TLD | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0491 | Microsoft OneDrive | Reversed-label typosquat ('com-' prefix) mimicking a OneDrive share notification landing page | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0492 | Microsoft Outlook | Doubled-character typosquat of 'outlook' on a cheap .site TLD | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0493 | Microsoft Outlook / OWA | Target-tailored webmail lure — victim org name appended to 'outlook-email-' for a bespoke OWA sign-in clone | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0494 | Microsoft 365 / OneDrive | Brand-squat document-share lure funnelling to a Microsoft credential prompt | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0495 | Microsoft 365 | Exact-brand-plus-suffix squat on .top TLD | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0496 | Microsoft 365 | Brand-plus-word squat used as an account-services / sign-in landing page | 2026-09-29 | phishunt.io newly registered Microsoft domains |
| mfs-0497 | Microsoft Entra ID / microsoftonline.com | Character-transposition typosquat ('olnine' for 'online') of login.microsoftonline.com | 2026-09-25 | phishunt.io newly registered Microsoft domains |
| mfs-0498 | Microsoft Entra ID | Entra-themed brand squat impersonating an identity/SSO re-enrolment portal | 2026-09-25 | phishunt.io newly registered Microsoft domains |
| mfs-0499 | Microsoft Teams | Teams 'update required' lure leading to a Microsoft sign-in prompt | 2026-09-25 | phishunt.io newly registered Microsoft domains |
| mfs-0500 | Microsoft Office 365 | Brand squat with regional suffix hosting an Office 365 credential page | 2026-09-25 | phishunt.io newly registered Microsoft domains |
| mfs-0501 | Microsoft OneDrive | Homoglyph typosquat (zero-for-O) of OneDrive — sibling of the already-tracked 0nedrive.space | 2026-09-25 | phishunt.io newly registered Microsoft domains |
| mfs-0502 | Microsoft Entra ID / microsoftonline.com | Insertion typosquat of microsoftonline.com posing as the Microsoft identity sign-in host | 2026-09-24 | phishunt.io newly registered Microsoft domains |
| mfs-0503 | Microsoft 365 | Brand squat presented as a Microsoft service/support provider portal with a sign-in step | 2026-09-24 | phishunt.io newly registered Microsoft domains |
| mfs-0504 | Microsoft 365 / OneDrive | Fake 'offline file' share notification leading to a Microsoft credential prompt | 2026-09-24 | phishunt.io newly registered Microsoft domains |
| mfs-0505 | Microsoft Outlook | Exact-brand squat on a novelty TLD, used for Outlook webmail sign-in lures | 2026-09-24 | phishunt.io newly registered Microsoft domains |
| mfs-0506 | Microsoft OneDrive | 'OneDrive sync error, re-authenticate' lure on a newly registered .top domain | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0507 | Microsoft 365 | Region-prefixed brand squat ('fra-' = Frankfurt) — part of a three-TLD cluster registered the same day | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0508 | Microsoft 365 | Region-prefixed brand squat, same-day cluster with fra-microsoft.com and fra-microsoft.store | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0509 | Microsoft 365 | Region-prefixed brand squat, same-day cluster with fra-microsoft.com and fra-microsoft.info | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0510 | Microsoft Outlook / OWA | Victim-specific BEC lure — target company name concatenated with 'outlook-company' for a tailored webmail sign-in | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0511 | Microsoft Outlook | Exact-brand squat on a novelty TLD | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0512 | Microsoft Outlook | Exact-brand squat on a novelty TLD, sibling registration to outlook.beer | 2026-09-23 | phishunt.io newly registered Microsoft domains |
| mfs-0513 | Microsoft 365 | Urgency-prefixed brand squat used for 'account will be suspended' credential-harvest pages | 2026-09-22 | phishunt.io newly registered Microsoft domains |
| mfs-0514 | Microsoft Teams | Reversed brand-order squat on .cloud serving a Teams meeting/file lure into a Microsoft sign-in | 2026-09-22 | phishunt.io newly registered Microsoft domains |
| mfs-0515 | Microsoft Teams | Doubled-character typosquat ('teamss') posing as a Teams file viewer requiring sign-in | 2026-09-22 | phishunt.io newly registered Microsoft domains |
| mfs-0516 | Microsoft Outlook Web Access | 'OWA update required' lure hosting an Outlook Web App sign-in clone | 2026-09-22 | phishunt.io newly registered Microsoft domains |
| mfs-0517 | Microsoft 365 / Outlook | Brand squat framed as a Microsoft messaging/notification service with a credential gate | 2026-09-22 | phishunt.io newly registered Microsoft domains |
| mfs-0518 | Microsoft 365 | Numeric-suffix brand squat — same disposable pattern as the previously tracked microsoft251207.com and 676132-microsoft.com | 2026-09-22 | phishunt.io newly registered Microsoft domains |

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

### mfs-0203 — Microsoft Teams

```text
https://msteamsinvitees.com/invitation
```

- **Domain:** `msteamsinvitees.com`
- **Technique:** typosquat brand-impersonation Teams invite lure
- **Detection:** Alert on newly-registered domains containing 'msteams' serving /invite or /invitation paths
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0204 — Microsoft Teams

```text
https://msteamsinvitees.com/invite/
```

- **Domain:** `msteamsinvitees.com`
- **Technique:** typosquat brand-impersonation Teams invite lure
- **Detection:** Flag off-Microsoft domains mimicking teams.microsoft.com invite flows
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0205 — Microsoft Teams

```text
https://msteamsinvitees.com/see/
```

- **Domain:** `msteamsinvitees.com`
- **Technique:** typosquat brand-impersonation Teams invite lure
- **Detection:** Hunt for 'msteamsinvitees' in proxy/DNS logs; not a Microsoft-owned domain
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0206 — Azure AD / Entra ID

```text
https://moregoonsrue.com/path/?error=login_required&error_description=AADSTS50058:+A+silent+sign-in+request+was+sent+but+no+user+is+signed+in.+The+cookies+used+to+represent+the+user's+session+were+not+sent+in+the+request+to+Azure+AD.+This+can+happen+if+the+user+is+using+Internet+Explorer+or+Edge
```

- **Domain:** `moregoonsrue.com`
- **Technique:** AiTM credential-harvest landing spoofing Azure AD error
- **Detection:** Alert on non-microsoft hosts whose URL query contains 'AADSTS50058' + 'error=login_required'
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0207 — Microsoft Outlook

```text
https://www.outlook-test.duckdns.org/
```

- **Domain:** `www.outlook-test.duckdns.org`
- **Technique:** Outlook credential phish on dynamic-DNS (duckdns) host
- **Detection:** Block/alert on *.duckdns.org hosting 'outlook'/'login' content targeting O365
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0208 — Microsoft Outlook

```text
http://outlook-test.duckdns.org/
```

- **Domain:** `outlook-test.duckdns.org`
- **Technique:** Outlook credential phish on dynamic-DNS (duckdns) host
- **Detection:** HTTP (non-TLS) Outlook-named duckdns subdomains are high-signal phishing IOCs
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0224 — Microsoft Teams

```text
https://teams-microsoft-download.com
```

- **Domain:** `teams-microsoft-download.com`
- **Technique:** typosquat / brand-impersonation domain (Teams installer lure)
- **Detection:** Alert on newly-registered domains combining 'teams'+'microsoft'+'download'; block at proxy/mail gateway
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0225 — Microsoft OneDrive

```text
https://onedrivedoc.cfd
```

- **Domain:** `onedrivedoc.cfd`
- **Technique:** typosquat on cheap .cfd TLD (OneDrive document-share lure)
- **Detection:** Flag 'onedrive' lookalikes on abused TLDs (.cfd/.sbs/.shop); hunt document-share redirect chains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0226 — Microsoft Teams

```text
https://microsoftsteam.online
```

- **Domain:** `microsoftsteam.online`
- **Technique:** typosquat (transposed 'steam'/'teams')
- **Detection:** Fuzzy-match Levenshtein against 'microsoftteams' on suspicious TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0227 — Microsoft 365

```text
https://microsoftapp.sbs
```

- **Domain:** `microsoftapp.sbs`
- **Technique:** typosquat brand-impersonation domain on .sbs TLD
- **Detection:** Block newly-registered 'microsoft*' domains on .sbs; correlate with NRD feeds
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0228 — Microsoft 365

```text
https://microsoft365-techsupport.com
```

- **Domain:** `microsoft365-techsupport.com`
- **Technique:** tech-support themed brand impersonation
- **Detection:** Hunt 'microsoft'+'techsupport'/'support' domain combos; check for fake help-desk sign-in forms
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0229 — Microsoft

```text
https://microsoft-techsupport.com
```

- **Domain:** `microsoft-techsupport.com`
- **Technique:** tech-support / help-desk themed brand impersonation
- **Detection:** Flag help-desk lures pairing 'microsoft' with 'support'; watch for callback-phishing tie-ins
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0230 — Microsoft

```text
https://micros0ftsolutions.com
```

- **Domain:** `micros0ftsolutions.com`
- **Technique:** homoglyph typosquat (zero-for-o in 'micros0ft')
- **Detection:** Regex for digit-substitution homoglyphs (micr0soft/micros0ft) in domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0231 — Microsoft

```text
https://info-microsoft.info
```

- **Domain:** `info-microsoft.info`
- **Technique:** typosquat brand-impersonation on .info TLD
- **Detection:** Block 'microsoft' lookalikes on .info; check for hosted credential-harvest pages
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0232 — Microsoft Outlook

```text
https://gaming-outlook.com
```

- **Domain:** `gaming-outlook.com`
- **Technique:** typosquat pairing 'outlook' with unrelated keyword
- **Detection:** Fuzzy-match 'outlook' domains against NRD feed; inspect for Outlook sign-in clone
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0233 — Microsoft Outlook

```text
https://outlooksignal.com
```

- **Domain:** `outlooksignal.com`
- **Technique:** typosquat brand-impersonation domain
- **Detection:** Levenshtein match on 'outlook*' NRDs; watch for OWA-styled login pages
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0234 — Microsoft Outlook

```text
https://outlookemails.shop
```

- **Domain:** `outlookemails.shop`
- **Technique:** typosquat on commerce .shop TLD
- **Detection:** Flag 'outlook' brand on .shop/.top TLDs; block via NRD + brand-monitor
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0235 — Microsoft Outlook

```text
https://outlookdestinations.com
```

- **Domain:** `outlookdestinations.com`
- **Technique:** typosquat brand-impersonation domain
- **Detection:** Hunt 'outlook'+generic-noun domains; verify against legit outlook.com/office.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0236 — Microsoft Teams

```text
https://microsoftteams.top
```

- **Domain:** `microsoftteams.top`
- **Technique:** typosquat on abused .top TLD
- **Detection:** Block 'microsoftteams' on non-Microsoft TLDs; correlate Teams-invite phishing lures
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0237 — Microsoft 365

```text
https://microsoftenline.site
```

- **Domain:** `microsoftenline.site`
- **Technique:** typosquat of 'microsoftonline' (dropped char) on .site TLD
- **Detection:** Fuzzy-match against 'microsoftonline'; flag single-char deletions on cheap TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0238 — Microsoft

```text
https://microsoft-nextgenalpha-ai-private-asset-forum.com
```

- **Domain:** `microsoft-nextgenalpha-ai-private-asset-forum.com`
- **Technique:** long-string 'AI/investment' themed brand-impersonation lure
- **Detection:** Alert on unusually long 'microsoft-*' hyphenated domains with finance/AI keywords
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0239 — Microsoft OneDrive

```text
https://com-onedrive-microsoftonline.com
```

- **Domain:** `com-onedrive-microsoftonline.com`
- **Technique:** deceptive subdomain-ordering typosquat ('com-onedrive-microsoftonline')
- **Detection:** Detect reversed/embedded 'microsoftonline' and 'onedrive' tokens in registrable domain
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0244 — Microsoft 365

```text
https://management.daengrentacar.com/meetings
```

- **Domain:** `management.daengrentacar.com`
- **Technique:** AiTM (Evilginx2) reverse-proxy credential/session-cookie theft — BigBear 2.0 PhaaS
- **Detection:** Flag non-Microsoft hosts proxying login.microsoftonline.com; 42 nodes on Vultr/The Constant Company; 'meetings' path lure
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0245 — Microsoft 365

```text
https://konceptenterprises.com
```

- **Domain:** `konceptenterprises.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Compromised legit domain fronting AiTM proxy; watch Referer/SNI to login.microsoftonline.com from this host
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0246 — Microsoft 365

```text
https://ccpipharma.com
```

- **Domain:** `ccpipharma.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Vultr-hosted node proxying Microsoft auth; alert on token/cookie relay to login.microsoftonline.com
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0247 — Microsoft 365

```text
https://annastudios-paros.com
```

- **Domain:** `annastudios-paros.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Compromised SMB domain used as AiTM front; monitor outbound proxy to Microsoft login
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0248 — Microsoft 365

```text
https://hotelmidtownsurat.com
```

- **Domain:** `hotelmidtownsurat.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Hospitality domain repurposed as AiTM proxy; flag Microsoft login relayed through non-MS host
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0249 — Microsoft 365

```text
https://dataclust.com
```

- **Domain:** `dataclust.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Vultr node proxying login.microsoftonline.com; watch for session-cookie exfiltration
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0250 — Microsoft 365

```text
https://cifutura.com
```

- **Domain:** `cifutura.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** AiTM front for M365; correlate with Constant Company/Vultr ASN hosting
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0251 — Microsoft 365

```text
https://hoaivt.com
```

- **Domain:** `hoaivt.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Non-MS host proxying Microsoft auth; alert on MFA-approval relay
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0252 — Microsoft 365

```text
https://dronalms.com
```

- **Domain:** `dronalms.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** LMS-styled domain fronting AiTM proxy; watch Referer to login.microsoftonline.com
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0253 — Microsoft 365

```text
https://virextec.com
```

- **Domain:** `virextec.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Vultr-hosted AiTM node; flag cookie relay to Microsoft auth endpoints
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0254 — Microsoft 365

```text
https://offtic.com
```

- **Domain:** `offtic.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Short 'off'/office-styled domain as AiTM front; monitor proxied M365 sign-ins
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0255 — Microsoft 365

```text
https://rootreseller.com
```

- **Domain:** `rootreseller.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** AiTM proxy node; correlate to BigBear 2.0 Vultr infrastructure
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0256 — Microsoft 365

```text
https://management.michaelmarcotte.com
```

- **Domain:** `management.michaelmarcotte.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** 'management' subdomain lure fronting AiTM; watch login.microsoftonline.com relay
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0257 — Microsoft 365

```text
https://kgsscans.com
```

- **Domain:** `kgsscans.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** 'scans'/document lure domain as AiTM front; flag proxied Microsoft auth
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0258 — Microsoft 365

```text
https://soil-management.com
```

- **Domain:** `soil-management.com`
- **Technique:** AiTM (Evilginx2) phishlet proxying M365 login — BigBear 2.0 PhaaS
- **Detection:** Compromised domain fronting AiTM proxy; monitor session-cookie theft to M365
- **Source:** CloudSEK TRIAD — https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign
- **Status:** active
- **First seen:** 2026-09-11

### mfs-0259 — Microsoft 365 / Entra ID

```text
https://security-server-page--chisomotf.replit.app/
```

- **Domain:** `security-server-page--chisomotf.replit.app`
- **Technique:** Credential-harvest kit hosted on abused Replit app hosting; page title cloned from the Entra ID 'Sign in to your account' screen
- **Detection:** Alert on proxy/DNS to *.replit.app hosts matching 'security-server-page--*' or 'security-server-landing-page--*' — legitimate business use of that naming pattern is essentially nil
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(url,like,~security-server-page--chisomotf~)
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0260 — Microsoft 365 / Entra ID

```text
https://security-server-page--jhalskov68.replit.app/
```

- **Domain:** `security-server-page--jhalskov68.replit.app`
- **Technique:** Same Replit-hosted credential-harvest kit; title 'Sign in to your account'
- **Detection:** Hunt Entra sign-in logs for successful auth immediately preceded by a referrer/user click to a *.replit.app host; block the whole replit.app apex for non-dev users
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(url,like,~jhalskov68~)
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0268 — Microsoft Teams

```text
http://www.teams-login.com/page/Wjl0doBMGUb/
```

- **Domain:** `www.teams-login.com`
- **Technique:** Dedicated typosquat domain (teams-login[.]com) serving per-victim tokenized landing pages under /page/<random>/
- **Detection:** Block the teams-login[.]com apex; hunt mail logs for links with a /page/<11-char base62>/ path — the token is the per-recipient tracking ID
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0269 — Microsoft Outlook

```text
https://outlook-email-2026.hstn.me/?i=1
```

- **Domain:** `outlook-email-2026.hstn.me`
- **Technique:** Free-hosting (hstn.me / Hostinger free tier) Outlook lure with ?i=1 stage parameter, same kit family as the already-tracked iceiy.com/hstn.me Spanish-language Outlook lures
- **Detection:** Blocklist the free-hosting apexes hstn.me, iceiy.com, rf.gd, epizy.com outright for corporate users — near-zero legitimate business traffic, heavy M365 phishing reuse
- **Source:** Phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0270 — Microsoft OneDrive / Microsoft 365

```text
https://intermezzoconsultoria.com.br/docs042/onedrive-verify-obf.html
```

- **Domain:** `intermezzoconsultoria.com.br`
- **Technique:** Compromised Brazilian consultancy site serving the obfuscated 'onedrive-verify-obf.html' kit — same file name as the already-tracked grupoimpaktu.ao and camisasdecolores.net instances
- **Detection:** High-fidelity hunt: any URL whose filename contains 'onedrive-verify-obf' on a non-Microsoft host; the kit is redeployed verbatim across compromised sites
- **Source:** Phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0272 — Microsoft 365 / Office

```text
https://soporte.offices-support.com/i/a5a87edd5408d4d4aa07fe6a4e23d3a2f
```

- **Domain:** `soporte.offices-support.com`
- **Technique:** Lookalike 'offices-support' domain with a Spanish 'soporte' subdomain; uses the same /i/<hash> landing path as the m365-microsoft.com and internal-alerts.com kits
- **Detection:** Look in proxy/DNS logs for *.offices-support.com and for /i/ followed by a 33-character hex path on non-Microsoft hosts
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0273 — Microsoft 365 / Office

```text
https://soporte.offices-support.com/form/a8247b3dc61a46a6a54aa1b5713bda72/a5a87edd5408d4d4aa07fe6a4e23d3a2f
```

- **Domain:** `soporte.offices-support.com`
- **Technique:** Credential-capture form on a lookalike Office support domain; a second step of the same /i/<hash> kit
- **Detection:** Alert on POSTs to /form/<32hex>/<33hex> paths and on any request to offices-support.com
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0274 — Microsoft 365 / Office

```text
http://ferdelmann.charles.office-share-microsoft.com/
```

- **Domain:** `ferdelmann.charles.office-share-microsoft.com`
- **Technique:** Lookalike combo-squat domain (office-share-microsoft) with a victim-name subdomain serving a fake Microsoft sign-in page
- **Detection:** Alert on DNS/proxy hits for *.office-share-microsoft.com and on subdomains shaped like firstname.lastname under new Microsoft-themed domains
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0275 — Microsoft Office 365

```text
http://www.ozatak.com/office
```

- **Domain:** `www.ozatak.com`
- **Technique:** Office credential-phishing page hosted under an /office path on a compromised or unrelated site
- **Detection:** Hunt proxy logs for POSTs to non-Microsoft hosts with /office paths that follow email link clicks
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0276 — Microsoft 365

```text
http://security.m365-microsoft.com/page/b61523c398fb47cd9e884313f5c33349/d51ee024a6cb3468996ec7c9307051d1d
```

- **Domain:** `security.m365-microsoft.com`
- **Technique:** Typosquat m365-microsoft.com phishing platform; /page/<32-hex>/<32-hex> landing variant of the /i/ link we already track
- **Detection:** Block all of *.m365-microsoft.com and match URL regex /(i|page)/[a-f0-9]{32,33}
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0277 — Microsoft 365 / Entra ID

```text
https://account-access-rc3uenqi.elitechiropracticandrehab.com
```

- **Domain:** `account-access-rc3uenqi.elitechiropracticandrehab.com`
- **Technique:** GhostCode device-code phishing (OAuth device authorization grant abusing the Microsoft Authentication Broker), delivered via a password-protected HTML file on WeTransfer
- **Detection:** Hunt Entra sign-in logs for authenticationProtocol=deviceCode with client ID 29d9ed98-a469-4536-ade2-f981bc1d605e, followed by fast device registration
- **Source:** eSentire — https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0278 — Microsoft 365 / Entra ID

```text
https://chartered.flipbookonlinevault.com
```

- **Domain:** `chartered.flipbookonlinevault.com`
- **Technique:** GhostCode relay and bot-filtering layer that redirects to the device-code phishing page via /scanna/<32-hex>/<64-hex> paths
- **Detection:** Match proxy URLs against the regex /scanna/[a-f0-9]{32}/[a-f0-9]{64} and the path /scanna/file001/
- **Source:** eSentire — https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0279 — Microsoft 365

```text
http://verificacion365.freepage.cc/
```

- **Domain:** `verificacion365.freepage.cc`
- **Technique:** Spanish-language 'Verificacion Microsoft' credential harvester on free hosting (freepage.cc)
- **Detection:** Look for *.freepage.cc hosts containing '365' or 'verificacion', and pages titled 'Verificacion Microsoft' that aren't on Microsoft domains
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0280 — Microsoft 365

```text
https://mxoff-standard-v.us-iad-10.linodeobjects.com/rsa.html
```

- **Domain:** `mxoff-standard-v.us-iad-10.linodeobjects.com`
- **Technique:** Fake 'Microsoft Security - Verify Your Identity' page hosted on Linode Object Storage
- **Detection:** Alert on *.linodeobjects.com HTML pages titled 'Microsoft Security - Verify Your Identity' or with 'mxoff' in the bucket name
- **Source:** OpenPhish — https://urlscan.io/search/#domain:mxoff-standard-v.us-iad-10.linodeobjects.com
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0290 — Microsoft 365 / Entra ID

```text
https://login-microsoftonline.pl/
```

- **Domain:** `login-microsoftonline.pl`
- **Technique:** Typosquat of login.microsoftonline.com on a .pl ccTLD, hosting a fake account-login lure
- **Detection:** Look for 'login-microsoftonline' on any TLD other than microsoftonline.com in DNS/proxy logs; hostname resolved to 85.128.128.104
- **Source:** PhishDestroy — https://phishdestroy.io/domain/login-microsoftonline.pl/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0291 — Microsoft 365 / Entra ID

```text
https://account-access-thlwvhxo.cxxzf.com/
```

- **Domain:** `account-access-thlwvhxo.cxxzf.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0292 — Microsoft 365 / Entra ID

```text
https://account-access-unlcjkmj.androidpreneur.com/
```

- **Domain:** `account-access-unlcjkmj.androidpreneur.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0293 — Microsoft 365 / Entra ID

```text
https://saml-access-bgzdiwai.pelicol.com/
```

- **Domain:** `saml-access-bgzdiwai.pelicol.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0294 — Microsoft 365 / Entra ID

```text
https://saml-access-hjg5zb1m.schuelerhvac.com/
```

- **Domain:** `saml-access-hjg5zb1m.schuelerhvac.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0295 — Microsoft 365 / Entra ID

```text
https://saml-access-fgphrx1b.geefjelevenkleur.com/
```

- **Domain:** `saml-access-fgphrx1b.geefjelevenkleur.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0296 — Microsoft 365 / Entra ID

```text
https://saml-access-0yni8zkk.deltarstar.com/
```

- **Domain:** `saml-access-0yni8zkk.deltarstar.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0297 — Microsoft 365 / Entra ID

```text
https://saml-access-qhtexulk.atomzilla.com/
```

- **Domain:** `saml-access-qhtexulk.atomzilla.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0298 — Microsoft 365 / Entra ID

```text
https://saml-access-ebntirhn.followmyitems.com/
```

- **Domain:** `saml-access-ebntirhn.followmyitems.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0299 — Microsoft 365 / Entra ID

```text
https://saml-access-umjn1zxd.vnamecard.com/
```

- **Domain:** `saml-access-umjn1zxd.vnamecard.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0300 — Microsoft 365 / Entra ID

```text
https://saml-access-whwhikxl.lygdhc.com/
```

- **Domain:** `saml-access-whwhikxl.lygdhc.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0301 — Microsoft 365 / Entra ID

```text
https://saml-access-4ejlnged.cciwedding.com/
```

- **Domain:** `saml-access-4ejlnged.cciwedding.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0302 — Microsoft 365 / Entra ID

```text
https://saml-access-vdjnpebo.alltoyotatrucksuvparts.com/
```

- **Domain:** `saml-access-vdjnpebo.alltoyotatrucksuvparts.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0303 — Microsoft 365 / Entra ID

```text
https://onestep-access-aosbgdan.tv-appspot.com/
```

- **Domain:** `onestep-access-aosbgdan.tv-appspot.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0304 — Microsoft 365 / Entra ID

```text
https://signin-access-3qbuumoo.alltoyotatrucksuvparts.com/
```

- **Domain:** `signin-access-3qbuumoo.alltoyotatrucksuvparts.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0305 — Microsoft 365 / Entra ID

```text
https://session-access-hrh9axw6.androidpreneur.com/
```

- **Domain:** `session-access-hrh9axw6.androidpreneur.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0306 — Microsoft 365 / Entra ID

```text
https://signin-access-ltcpr2s7.breakingpandora.com/
```

- **Domain:** `signin-access-ltcpr2s7.breakingpandora.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0307 — Microsoft 365 / Entra ID

```text
https://secure-access-ht0ysxlq.alltoyotatrucksuvparts.com/
```

- **Domain:** `secure-access-ht0ysxlq.alltoyotatrucksuvparts.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0308 — Microsoft 365 / Entra ID

```text
https://verify-access-umjlvvrx.alltoyotatrucksuvparts.com/
```

- **Domain:** `verify-access-umjlvvrx.alltoyotatrucksuvparts.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0309 — Microsoft 365 / Entra ID

```text
https://signin-access-bpbippyw.geefjelevenkleur.com/
```

- **Domain:** `signin-access-bpbippyw.geefjelevenkleur.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0310 — Microsoft 365 / Entra ID

```text
https://mfa-access-pyvxbnjc.atomzilla.com/
```

- **Domain:** `mfa-access-pyvxbnjc.atomzilla.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0311 — Microsoft 365 / Entra ID

```text
https://signin-access-whtc5iq4.accudiodesign.com/
```

- **Domain:** `signin-access-whtc5iq4.accudiodesign.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0312 — Microsoft 365 / Entra ID

```text
https://authenticate-access-unb5gtsf.xhscyp.com/
```

- **Domain:** `authenticate-access-unb5gtsf.xhscyp.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0313 — Microsoft 365 / Entra ID

```text
https://validate-access-kgcdauwc.xhscyp.com/
```

- **Domain:** `validate-access-kgcdauwc.xhscyp.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0314 — Microsoft 365 / Entra ID

```text
https://verify-access-6dlrv01r.adogabroad.com/
```

- **Domain:** `verify-access-6dlrv01r.adogabroad.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0315 — Microsoft 365 / Entra ID

```text
https://identity-access-1w2m8s2x.arlingtonhousecleaning.com/
```

- **Domain:** `identity-access-1w2m8s2x.arlingtonhousecleaning.com`
- **Technique:** GhostCode device-code phishing kit on compromised-site subdomain; abuses OAuth device code flow, registers Entra devices, steals PRT
- **Detection:** Hunt DNS/proxy for subdomains matching (saml|signin|account|mfa|verify|secure|session|identity|validate|authenticate|onestep)-access-[a-z0-9]{8} plus Entra deviceCode sign-ins followed by device registration
- **Source:** eSentire — https://github.com/eSentire/iocs/blob/main/GhostCode/GhostCode-iocs-09-09-2026.txt
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0316 — Microsoft 365 / Entra ID

```text
https://flipbookviewer.us/
```

- **Domain:** `flipbookviewer.us`
- **Technique:** GhostCode relay / decoy PDF host that redirects to the device-code phishing kit
- **Detection:** Flag flipbook-themed domains that redirect via /scanna/ paths or /turnstile?return_url= to *-access-* hosts
- **Source:** eSentire — https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0317 — Microsoft 365

```text
https://authentication.ms/E.4kAyc5YXlYaw1ZYv
```

- **Domain:** `authentication.ms`
- **Technique:** Lookalike domain on the .ms ccTLD posing as a Microsoft authentication short link
- **Detection:** Flag outbound requests to authentication.ms or other non-Microsoft .ms domains that use auth-themed words
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0318 — Microsoft

```text
http://microsoft.authorised-support.com/login/kJvS3f0yuChJ2iiGTFV1GPPm9iva0DjA7VkI=8CQ==2X1tRQF1BXVRGbV5dVVtcbUVbRlptQlNBQUVdQFY=/nvt3NKMwtzP_DxN-w4HypHCzle-pHdq6/
```

- **Domain:** `microsoft.authorised-support.com`
- **Technique:** Fake support domain with a per-victim encoded token in the /login/ path
- **Detection:** Hunt for *.authorised-support.com URLs whose /login/ path contains base64-like tokens with '==' in the middle
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0319 — Microsoft

```text
http://microsoft.authorised-support.com/login/kJvS3f0yuChJ2iiGTFV1GPPm9iva0DjA7VkI=8CQ==/nvt3NKMwtzP_DxN-w4HypHCzle-pHdq6/
```

- **Domain:** `microsoft.authorised-support.com`
- **Technique:** Fake support domain with a shorter per-victim token in the /login/ path
- **Detection:** Match the regex authorised-support\.com/login/[A-Za-z0-9=_-]+/ in proxy logs
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0343 — Microsoft 365

```text
https://chartered.flipbookonlinevault.com/scanna/200e61bfe54c92fb720c77c3a1661bc0/b5ea87c2ddac3aa141bc6794b8993d1e43bd064eaae591719612becea0d106d7
```

- **Domain:** `chartered.flipbookonlinevault.com`
- **Technique:** GhostCode kit: password-protected HTML attachment leads to a bot-filtering relay, then Microsoft device-code phishing via the Authentication Broker
- **Detection:** Hunt for /scanna/<32hex>/<64hex> URL paths and device-code sign-ins using app ID 29d9ed98-a469-4536-ade2-f981bc1d605e
- **Source:** eSentire via Cyber Security News — https://cybersecuritynews.com/ghostcode-phishing-kit/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0344 — Microsoft 365

```text
https://msoft-common-gbz-8999.us-sea-1.linodeobjects.com/cloudzymsfto.html
```

- **Domain:** `msoft-common-gbz-8999.us-sea-1.linodeobjects.com`
- **Technique:** Fake Microsoft sign-in page hosted on Linode (Akamai) Object Storage bucket, like the earlier mxoff linodeobjects.com lure
- **Detection:** Hunt proxy/DNS logs for *.linodeobjects.com requests with msoft/mxoff/office bucket names or .html paths, followed by a POST to an off-Microsoft host
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0349 — Microsoft 365

```text
https://chartered.flipbookonlinevault.com/scanna/file001//
```

- **Domain:** `chartered.flipbookonlinevault.com`
- **Technique:** GhostCode device-code phishing: flipbook relay with bot filtering, reached from a password-protected HTML attachment in WeTransfer, redirects to a fake account-access sign-in page
- **Detection:** Alert on /scanna/ paths on flipbook* domains followed by a deviceCode sign-in and several Intune/DRS device registrations within minutes
- **Source:** eSentire TRU — https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0350 — Microsoft Outlook

```text
http://connectezvousamicrosoftoutlook.weebly.com/
```

- **Domain:** `connectezvousamicrosoftoutlook.weebly.com`
- **Technique:** Free-site-builder phishing (Weebly) with a French-language 'connect to Microsoft Outlook' credential lure
- **Detection:** Flag *.weebly.com subdomains containing microsoft/outlook/connectez strings; alert on credential POSTs from free site-builder hosts
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-21

### mfs-0351 — Microsoft 365 / Outlook

```text
https://auth.properties/E.rU-TDP5DOv4?/microsoftonline/mailbox/upgrade&userid=75468973984785978212312307887543
```

- **Domain:** `auth.properties`
- **Technique:** AiTM short-token lure (same /E.<token> path pattern as the authentication.ms kit) disguised as a 'microsoftonline mailbox upgrade'
- **Detection:** Hunt for URL paths matching ^/E\.[A-Za-z0-9_-]{8,}\? that contain 'microsoftonline' on domains that are not Microsoft's
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0352 — Microsoft 365

```text
https://multi-factor.link/E.St5UcG6gsr285ASjcg?/ContextID=O365
```

- **Domain:** `multi-factor.link`
- **Technique:** AiTM MFA lure: a fake 'multi-factor' domain using the /E.<token> kit pattern with ContextID=O365
- **Detection:** Block the multi-factor.link apex and alert on 'ContextID=O365' in query strings for non-Microsoft hosts
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0353 — Microsoft 365

```text
https://multi-factor.link/E.pjjzfMPMCJolyCvBXg?/ContextID=O365
```

- **Domain:** `multi-factor.link`
- **Technique:** AiTM MFA lure: a second token on the same multi-factor.link kit infrastructure
- **Detection:** Look in proxy logs for any request to multi-factor.link with an /E.<token> path
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0354 — Microsoft Teams / Microsoft 365

```text
https://authentication.ms/E.YmqG6CR_vI9i?/domain=iberdrola.es?teams=Collaborative-Teams?profile=info
```

- **Domain:** `authentication.ms`
- **Technique:** AiTM lookalike .ms domain with a Teams collaboration lure aimed at a specific tenant (iberdrola.es)
- **Detection:** Alert on authentication.ms (a lookalike, not a Microsoft domain) and on 'teams=Collaborative-Teams' in the URL
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0355 — Microsoft 365

```text
https://m365-online.ch/?rid=rR2FqXp
```

- **Domain:** `m365-online.ch`
- **Technique:** Typosquat domain that tracks each victim with a ?rid= campaign ID (GoPhish-style)
- **Detection:** Flag newly registered domains containing 'm365' plus a ?rid= parameter in email links
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0356 — Microsoft OneDrive / Microsoft 365

```text
https://moripartnerch-365-mso-drive-auth9287364.cloud-storage-id0384723.workers.dev/
```

- **Domain:** `moripartnerch-365-mso-drive-auth9287364.cloud-storage-id0384723.workers.dev`
- **Technique:** Credential page hosted on Cloudflare Workers, with a subdomain that mimics '365 mso drive auth'
- **Detection:** Hunt for *.workers.dev hostnames containing '365' together with 'drive' or 'auth'
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0357 — Microsoft 365

```text
https://xn--knto-55d.evergreenfin.ltd/
```

- **Domain:** `xn--knto-55d.evergreenfin.ltd`
- **Technique:** Punycode homoglyph 'konto' subdomain on known Microsoft phishing infrastructure (evergreenfin.ltd)
- **Detection:** Block all of *.evergreenfin.ltd and alert on xn-- labels in sign-in links
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0358 — Microsoft Teams

```text
https://s.teams-ra.com/p/fjbd-cbch/jtzuihmh/
```

- **Domain:** `s.teams-ra.com`
- **Technique:** Teams-lookalike domain serving a tokenized /p/<id>/<id>/ redirect to a credential page
- **Detection:** Flag non-Microsoft domains containing 'teams-' that use short /p/xxxx-xxxx/ paths
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0359 — Microsoft 365

```text
http://adi-panwar.github.io/Microsoft
```

- **Domain:** `adi-panwar.github.io`
- **Technique:** Free-hosting phish (GitHub Pages) with a Microsoft-branded path posing as a sign-in page
- **Detection:** Flag *.github.io URLs whose path contains Microsoft/Office/Outlook and whose page includes a password field
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0360 — Microsoft 365 (Excel)

```text
https://nk2184.craftum.io/
```

- **Domain:** `nk2184.craftum.io`
- **Technique:** Fake 'Microsoft Excel 2026 Document Access' page that collects email and password, hosted on the Craftum site builder
- **Detection:** Flag *.craftum.io pages with 'Microsoft Excel' or 'Enter your credentials to access documents' plus a password field; AS9123 Timeweb
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11911122)
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0361 — Outlook Web App

```text
https://bnimail-owa.vercel.app/
```

- **Domain:** `bnimail-owa.vercel.app`
- **Technique:** Clone of an OWA/Exchange login page ('BNI Outlook') on Vercel free hosting, targeting one organisation's webmail
- **Detection:** Hunt *.vercel.app hostnames containing 'owa' or 'mail' that serve OWA 'Domain\User ID' login forms
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11910573)
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0362 — Microsoft 365

```text
https://security-server-landing-page--lme85959.replit.app/
```

- **Domain:** `security-server-landing-page--lme85959.replit.app`
- **Technique:** Microsoft 'Enter password / sign in timed-out' clone on Replit; same template as the existing security-server-page campaign
- **Detection:** Block *.replit.app hostnames matching 'security-server-(landing-)?page--*'
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11910585)
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0363 — Microsoft 365

```text
https://security-server-landing-page--spencer-hunt1.replit.app/
```

- **Domain:** `security-server-landing-page--spencer-hunt1.replit.app`
- **Technique:** Microsoft 'Enter password / sign in timed-out' clone on Replit; same template as the existing security-server-page campaign
- **Detection:** Block *.replit.app hostnames matching 'security-server-(landing-)?page--*'
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11910577)
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0364 — Microsoft 365

```text
https://teamliftss.com/zz/index.html
```

- **Domain:** `teamliftss.com`
- **Technique:** Microsoft sign-in clone ('To access document, you'll need to verify your account') on a lookalike or compromised domain
- **Detection:** Look for the page text 'That Microsoft account doesn't exist' served from non-Microsoft domains under short paths like /zz/
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11909593)
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0365 — Microsoft 365

```text
https://bx.wsapbfy.net/leona.denesha/tessere.html
```

- **Domain:** `bx.wsapbfy.net`
- **Technique:** Fake 'Document Access Verification' page with Microsoft Corporation branding that asks for an email address; path is personalised to the victim
- **Detection:** Alert on HTML pages whose path contains a firstname.lastname segment and whose body has 'Document Access Required' plus a Microsoft footer
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11909051)
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0366 — Microsoft account (Outlook/Hotmail)

```text
https://comunidad--comunidadunitec.replit.app/
```

- **Domain:** `comunidad--comunidadunitec.replit.app`
- **Technique:** Spanish-language fake 'Microsoft Services Agreement updated' page on Replit; same kit as office-365-msn--oficeer.replit.app
- **Detection:** Hunt *.replit.app pages containing 'se actualizó el contrato de servicios de Microsoft'
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11908780)
- **Status:** active
- **First seen:** 2026-09-15

### mfs-0367 — Microsoft OneDrive / Office 365

```text
https://penielpeters44-spec.github.io/payit/Statement%20POP.html
```

- **Domain:** `penielpeters44-spec.github.io`
- **Technique:** 'Proof Of Payment' OneDrive lure hosted on GitHub Pages that asks for the victim's Microsoft email
- **Detection:** Flag github.io pages titled 'Proof Of Payment' that ask to 'Login with your microsoft email account'
- **Source:** PhishStats — https://api.phishstats.info/api/phishing?_where=(id,eq,11908484)
- **Status:** active
- **First seen:** 2026-09-14

### mfs-0368 — Microsoft account / Outlook

```text
http://security-server-page--emekemine206.replit.app/
```

- **Domain:** `security-server-page--emekemine206.replit.app`
- **Technique:** Fake 'Security verification - Microsoft account' credential-harvest page on a free Replit app subdomain (security-server-page-- template)
- **Detection:** Alert on *.replit.app hosts starting with 'security-server-page--' or 'security-server-landing-page--' and page titles containing 'Microsoft account'
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0369 — Microsoft account / Outlook

```text
http://security-server-landing-page--mariodrichard.replit.app/
```

- **Domain:** `security-server-landing-page--mariodrichard.replit.app`
- **Technique:** Same Replit 'security-server-landing-page--' Microsoft account verification template seen in earlier replit.app lures
- **Detection:** Block or hunt *.replit.app subdomains matching 'security-server-(landing-)?page--*' in proxy and DNS logs
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0370 — Microsoft 365

```text
https://roechling.site/login.html
```

- **Domain:** `roechling.site`
- **Technique:** Brand typosquat (Röchling) on a 4-day-old Cloudflare-fronted domain hosting a cloned Entra ID sign-in page
- **Detection:** Flag new .site domains whose page title is 'Sign in to your account' and that are hosted outside Microsoft's IP ranges
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bee7-b367-7676-84f0-b5c3324aa5ad/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0371 — Microsoft 365

```text
https://security-server-landing-page--microsoftdou.replit.app/
```

- **Domain:** `security-server-landing-page--microsoftdou.replit.app`
- **Technique:** Free-hosting abuse (Replit) using the 'security-server-landing-page--<user>' AiTM lure series
- **Detection:** Block the regex ^security-server(-landing|-static|-website)?(-page)?--.*\.replit\.app$
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bee7-ab8d-74ae-9bd3-cda609673ca6/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0372 — Microsoft account

```text
http://security-server-page--delta2rolspan.replit.app/
```

- **Domain:** `security-server-page--delta2rolspan.replit.app`
- **Technique:** Replit-hosted fake 'Security verification - Microsoft account' page
- **Detection:** Replit subdomains titled 'Security verification - Microsoft account'
- **Source:** OpenPhish / PhishTank (via urlscan.io) — https://urlscan.io/result/01a0ba9c-e058-769e-81c3-781445bc983e/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0373 — Microsoft 365

```text
https://security-server-page--heainjus1.replit.app/
```

- **Domain:** `security-server-page--heainjus1.replit.app`
- **Technique:** Replit-hosted cloned Entra ID sign-in page (same kit series as known replit.app entries)
- **Detection:** Any *.replit.app page titled 'Sign in to your account'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace3-e9a7-7607-8cdd-602435aec83c/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0374 — Microsoft account

```text
http://security-server-website--resultbox63.replit.app/
```

- **Domain:** `security-server-website--resultbox63.replit.app`
- **Technique:** Replit-hosted fake Microsoft security verification page
- **Detection:** Match 'security-server-website--' prefix on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0af77-6805-714c-afaf-c8df329e4222/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0375 — Microsoft 365

```text
https://security-server--eplkaasi.replit.app/
```

- **Domain:** `security-server--eplkaasi.replit.app`
- **Technique:** Replit-hosted Microsoft sign-in clone
- **Detection:** Match 'security-server--' prefix on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace2-9531-738a-9847-0fe56cdc8191/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0376 — Microsoft 365

```text
https://security-server-landing-page--chriswazza79.replit.app/
```

- **Domain:** `security-server-landing-page--chriswazza79.replit.app`
- **Technique:** Replit-hosted Microsoft sign-in clone
- **Detection:** Match 'security-server-landing-page--' on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace2-9921-7209-b64e-61c5626ec4ee/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0377 — Microsoft 365

```text
https://security-server-landing-page--mauricemslatter.replit.app/?naps
```

- **Domain:** `security-server-landing-page--mauricemslatter.replit.app`
- **Technique:** Replit-hosted sign-in clone reached through the '?naps' lure parameter
- **Detection:** Watch for the '?naps' query string on free-hosting domains
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace1-54bf-72aa-bc7b-bbf8e7a2d607/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0378 — Microsoft 365

```text
https://security-server-landing-page--retrobob.replit.app/?naps
```

- **Domain:** `security-server-landing-page--retrobob.replit.app`
- **Technique:** Replit-hosted Microsoft sign-in clone
- **Detection:** Match 'security-server-landing-page--' on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0aa50-8b7d-71be-a2a3-7783e788c0b9/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0379 — Microsoft account

```text
http://security-server-landing-page--aghnakazmi.replit.app/
```

- **Domain:** `security-server-landing-page--aghnakazmi.replit.app`
- **Technique:** Replit-hosted fake Microsoft security verification page
- **Detection:** Match 'security-server-landing-page--' on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0aa4e-bc37-74e6-aba6-4aa32bb9db41/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0380 — Microsoft account

```text
http://security-server-static-page--raymondhug.replit.app/
```

- **Domain:** `security-server-static-page--raymondhug.replit.app`
- **Technique:** Replit-hosted fake Microsoft security verification page
- **Detection:** Match 'security-server-static-page--' on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0aa51-175f-77be-90ad-14da38491f92/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0381 — Microsoft account

```text
https://server-security-landing-page--docu-sign.replit.app/
```

- **Domain:** `server-security-landing-page--docu-sign.replit.app`
- **Technique:** DocuSign-themed lure leading to a fake Microsoft security verification page on Replit
- **Detection:** Replit subdomains that combine 'docu-sign' or 'docusign' with a Microsoft page title
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bee7-02ec-7218-a239-99ee4bb72b75/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0382 — Microsoft account

```text
https://docusignfile-review-security-page--newstoolin.replit.app/?naps
```

- **Domain:** `docusignfile-review-security-page--newstoolin.replit.app`
- **Technique:** DocuSign document lure that harvests Microsoft credentials on Replit
- **Detection:** Match 'docusignfile-review' on replit.app
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace0-e33d-7668-b8ae-187c97f804e0/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0383 — Microsoft account

```text
https://secure-html-editor--bradleyevans200.replit.app/
```

- **Domain:** `secure-html-editor--bradleyevans200.replit.app`
- **Technique:** Replit-hosted 'Sign in to your Microsoft account' clone
- **Detection:** *.replit.app pages titled 'Sign in to your Microsoft account'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace3-7b14-7108-92ea-535eea8e781a/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0384 — Outlook Web App

```text
https://mail-us-exg07-exgh0st-0wa.replit.app/
```

- **Domain:** `mail-us-exg07-exgh0st-0wa.replit.app`
- **Technique:** Fake Exchange/OWA page on Replit, reached through the tracking redirect user.mxredwood.com
- **Detection:** Replit subdomains containing 'owa', '0wa' or 'exg'; also watch mxredwood.com redirects
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace3-6052-71ba-9cd2-1c158efc87bb/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0385 — Outlook

```text
https://ed-art-page.replit.app/about.html
```

- **Domain:** `ed-art-page.replit.app`
- **Technique:** 'Continue to Outlook' credential page on Replit
- **Detection:** Replit pages titled 'Continue to Outlook'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b49c-b434-7746-8f37-486559a2b437/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0386 — Microsoft account

```text
http://my-html-app-production-wsufv2.laravel.cloud/new.html
```

- **Domain:** `my-html-app-production-wsufv2.laravel.cloud`
- **Technique:** Laravel Cloud free-hosting abuse serving a fake Microsoft security verification page
- **Detection:** *.laravel.cloud static HTML pages with Microsoft titles
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0af74-ba93-70bc-8ab0-f3dc7d57e2d6/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0387 — Microsoft account

```text
https://fls-a2c06490-fc61-4ef8-95a7-68d9b72fbce7.laravel.cloud/myown.html
```

- **Domain:** `fls-a2c06490-fc61-4ef8-95a7-68d9b72fbce7.laravel.cloud`
- **Technique:** Laravel Cloud 'fls-<uuid>' file-hosting abuse (same pattern as the known hotmail inbox page)
- **Detection:** Block fls-*.laravel.cloud pages with .html paths
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0a7bd-0c07-7269-bdb2-d07c4b20b76b/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0388 — Hotmail / Microsoft account

```text
https://usc1.contabostorage.com/3afb0c8c107a4058aec51787070d029f:newnew/hotmail.html
```

- **Domain:** `usc1.contabostorage.com`
- **Technique:** Contabo object-storage bucket hosting a Hotmail credential page
- **Detection:** contabostorage.com URLs whose path ends in hotmail/obum/.html
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bc55-eafa-75bd-8886-466a0be50864/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0389 — Microsoft 365

```text
https://usc1.contabostorage.com/e2dce81f193044d09b18133ea4583e24:azzzzz/obum.html
```

- **Domain:** `usc1.contabostorage.com`
- **Technique:** Contabo object-storage bucket hosting a Microsoft sign-in clone
- **Detection:** Object-storage HTML pages titled 'Sign in to your account'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b9c2-c0fc-7131-a75b-060cda7718d2/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0390 — Hotmail / Microsoft account

```text
https://light.s-drc2.cloud.gcore.lu/newhot26.html
```

- **Domain:** `light.s-drc2.cloud.gcore.lu`
- **Technique:** Gcore object-storage bucket hosting a fake Microsoft security verification page
- **Detection:** cloud.gcore.lu HTML files named hot*/newhot*
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0aa4d-f5da-764c-a23a-d6551b49c7aa/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0391 — Hotmail / Microsoft account

```text
https://paymob.shop/hotmailsss/hotnew.html
```

- **Domain:** `paymob.shop`
- **Technique:** Microsoft verification clone on a 15-day-old domain
- **Detection:** Paths containing 'hotmail' on newly registered .shop domains
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b9c1-c134-705b-9f70-ef8b6f6f20e5/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0392 — Microsoft account

```text
https://lobologisticgroup.com.mx/ds/kmgroup.html
```

- **Domain:** `lobologisticgroup.com.mx`
- **Technique:** Compromised site hosting a fake Microsoft security verification page (also served on the kkms. subdomain)
- **Detection:** Legitimate SMB domains suddenly serving 'Security verification - Microsoft account'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bc56-0b0b-7109-b49d-997696a30b3b/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0393 — Microsoft account

```text
https://www.kkms.lobologisticgroup.com.mx/
```

- **Domain:** `www.kkms.lobologisticgroup.com.mx`
- **Technique:** Subdomain on a compromised site serving a Microsoft verification phish
- **Detection:** New subdomains on compromised .com.mx hosts
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bee7-a519-738f-9f1e-873a2bec5d55/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0394 — Microsoft account

```text
https://subseguirias.xyz/wp-css/project_drawings.html
```

- **Domain:** `subseguirias.xyz`
- **Technique:** Fake 'project drawings' document lure in a WordPress-like path leading to Microsoft verification
- **Detection:** Paths like /wp-css/*.html that are not real WordPress paths
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b49a-98a3-717a-8bc9-8ec58243bcb3/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0395 — Microsoft 365

```text
https://channelhub.online/a2240a74cg969843d86a17f4ea4de1a498a1.html
```

- **Domain:** `channelhub.online`
- **Technique:** Sign-in clone behind a random-hex HTML path per victim; the page 404s after first use
- **Detection:** Hex-named single-use .html paths titled 'Sign in to your account'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bc56-121a-70e8-975c-cde7c8ab9ef0/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0396 — Microsoft 365

```text
https://zyexx.com/v6bac5ea345aa94405bb69c9d9bxa2a8955f.html
```

- **Domain:** `zyexx.com`
- **Technique:** Same random-hex HTML path kit as channelhub.online
- **Detection:** Paths matching /[a-z0-9]{36}\.html with Microsoft titles
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace1-6378-7469-b9fd-fc25188d2e82/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0397 — Outlook / Exchange

```text
http://timeforgoldens.com/exchange-portal/index.html
```

- **Domain:** `timeforgoldens.com`
- **Technique:** Compromised site hosting a fake Exchange/Outlook portal
- **Detection:** '/exchange-portal/' paths on non-Microsoft hosts
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0c40d-b716-769d-bce4-5a2742863d36/
- **Status:** active
- **First seen:** 2026-09-21

### mfs-0398 — Microsoft / Hotmail

```text
http://login.bugcutter.com/rak/email/KYC-1/Compliance/hot
```

- **Domain:** `login.bugcutter.com`
- **Technique:** KYC-compliance email lure leading to a 'Microsoft | Login' page (mirrored on the hotspot. subdomain)
- **Detection:** URL paths containing /KYC-1/Compliance/
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bee8-19d5-71da-a8ff-7bda5a7fcd99/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0399 — Outlook

```text
https://acces-opalecenter.countmup.site/
```

- **Domain:** `acces-opalecenter.countmup.site`
- **Technique:** Outlook login clone on a lookalike subdomain of a .site domain
- **Detection:** Subdomains starting 'acces-' on young .site domains
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0bee7-4273-75b9-9c24-990f2d690d4e/
- **Status:** active
- **First seen:** 2026-09-20

### mfs-0400 — Microsoft OneDrive

```text
https://mail-drive-oj1g.p-2f66mze8.workers.dev/l/GfcQaj4x9c4/
```

- **Domain:** `mail-drive-oj1g.p-2f66mze8.workers.dev`
- **Technique:** Cloudflare Workers lure: 'Microsoft User shared a document with you'
- **Detection:** workers.dev pages titled 'shared a document with you'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b9c0-a55b-76db-ba48-9ef1feab5171/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0401 — Microsoft OneDrive

```text
http://divine-sea-8f82.jernzen26.workers.dev/4e83d1d11eed7769/d3d25a953d0222c296edeb
```

- **Domain:** `divine-sea-8f82.jernzen26.workers.dev`
- **Technique:** Chain of Cloudflare Workers redirects ending on a fake OneDrive page
- **Detection:** Watch for redirects between two *.workers.dev hosts that end on a OneDrive-titled page
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0c40e-679a-7618-98bc-55fd3318d4a0/
- **Status:** active
- **First seen:** 2026-09-21

### mfs-0402 — Microsoft OneDrive

```text
https://www.smmrgv.vercel.app/
```

- **Domain:** `www.smmrgv.vercel.app`
- **Technique:** Vercel-hosted 'My Files - OneDrive' credential lure
- **Detection:** *.vercel.app pages with OneDrive titles
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace2-0497-7250-a111-104ee0db7ded/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0403 — Office / OWA

```text
https://adobfilem.github.io/
```

- **Domain:** `adobfilem.github.io`
- **Technique:** GitHub Pages 'Office Web Access' credential page
- **Detection:** github.io pages titled 'Office Web Access'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b20b-2100-771c-aa7a-0d602bf4e3bf/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0404 — Outlook

```text
https://hyqdeapmec2.webflow.io/
```

- **Domain:** `hyqdeapmec2.webflow.io`
- **Technique:** Webflow-hosted 'Outlook Self Service Portal' reached through the shortener alturl.com/acaqd
- **Detection:** webflow.io sites titled Outlook; alturl.com shortener redirects
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b20b-3062-7618-923f-6df25093884d/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0405 — Microsoft OneDrive

```text
https://intermezzoconsultoria.com.br/luislopez/primasmaintenanceopendocaccess.html
```

- **Domain:** `intermezzoconsultoria.com.br`
- **Technique:** Compromised site hosting a per-victim OneDrive 'Access your file' lure (same host as a known entry)
- **Detection:** Block all .html paths under intermezzoconsultoria.com.br
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace2-1cce-769e-8df3-df769df93482/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0406 — Microsoft OneDrive

```text
https://intermezzoconsultoria.com.br/pmginspections/MarissaGodbold.html
```

- **Domain:** `intermezzoconsultoria.com.br`
- **Technique:** Personalized OneDrive file-access lure named after the victim
- **Detection:** HTML files named after people, titled 'Access your file - OneDrive'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0a7bc-3911-7544-8754-08874b752cba/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0407 — Microsoft Entra ID

```text
https://itsecuredesk.co.uk/?r=e7c0421b-a157-46d9-b193-06a6f48b28e0&rg=eu
```

- **Domain:** `itsecuredesk.co.uk`
- **Technique:** Fake IT-helpdesk domain serving a 'Microsoft SSO Sign In' page with per-victim GUID tokens
- **Detection:** Helpdesk-themed domains with ?r=<GUID>&rg= parameters
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0ace2-0c6a-7437-8945-e2f34a4c13ac/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0408 — Microsoft account

```text
https://x7tq54amsloginx7tq92.portal-login-access.net/
```

- **Domain:** `x7tq54amsloginx7tq92.portal-login-access.net`
- **Technique:** Randomized 'msslogin' subdomain on a generic portal-login domain
- **Detection:** Subdomains containing 'mslogin'/'amslogin' under portal-login-access.net
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0a7bd-5af9-75af-9288-61f26a2d86b6/
- **Status:** active
- **First seen:** 2026-09-16

### mfs-0409 — Microsoft account

```text
https://135461223.site/1782/776e774d-5054-475b-a189-76e40aed5241/757934
```

- **Domain:** `135461223.site`
- **Technique:** Numeric-domain 'Microsoft Login' page with a GUID tracking path
- **Detection:** All-digit .site domains titled 'Microsoft Login'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b49c-2634-71dc-8fa0-2cc48a19e486/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0410 — Microsoft account

```text
http://background-check-status.com/6197094-oH1faBZb-PKS9Q
```

- **Domain:** `background-check-status.com`
- **Technique:** Background-check lure leading to a 'Microsoft Login Page'
- **Detection:** HR or background-check themed domains titled 'Microsoft Login'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b20b-67e8-7713-9aab-4ea9bba71e57/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0411 — Microsoft 365 (AXA lure)

```text
https://it.one-axa.com/i/d9f45458d22584b169f6a906dd3fb284e
```

- **Domain:** `it.one-axa.com`
- **Technique:** Brand-lookalike domain using the /i/<hash> kit also seen on m365-microsoft.com and offices-support.com
- **Detection:** Paths matching /i/d[0-9a-f]{32}
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b72e-0eff-72d6-b2c2-b98d89b570d1/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0412 — Microsoft account (ES)

```text
http://www.reactiva-tucuentaa.iceiy.com/
```

- **Domain:** `www.reactiva-tucuentaa.iceiy.com`
- **Technique:** Spanish 'Verificacion Microsoft' page on iceiy.com free hosting, spread via the shortener i.gal/8OhE3
- **Detection:** iceiy.com / freepage.cc / zya.me pages titled 'Verificacion Microsoft'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b207-a553-74a1-a769-ef29cca83356/
- **Status:** active
- **First seen:** 2026-09-18

### mfs-0413 — Microsoft account (ES)

```text
http://infcuenta26.freepage.cc/
```

- **Domain:** `infcuenta26.freepage.cc`
- **Technique:** Spanish-language Microsoft verification phish on freepage.cc
- **Detection:** freepage.cc subdomains with 'cuenta' or '365'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0af73-f0b9-73ee-ac44-f684527d1923/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0414 — Microsoft account (ES)

```text
https://goo.su/mFWfpK
```

- **Domain:** `goo.su`
- **Technique:** goo.su shortener redirecting to renovacion365.zya.me ('Verificacion Microsoft')
- **Detection:** Block the renovacion365.zya.me host and goo.su links that lead to it
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0b72f-c03f-75ab-9587-20722a6c4d5d/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0415 — Microsoft account (ES)

```text
http://loginemailservices.yzz.me/
```

- **Domain:** `loginemailservices.yzz.me`
- **Technique:** 'Iniciar sesión en tu cuenta Microsoft' clone on yzz.me free hosting
- **Detection:** yzz.me / hstn.me / alc.onl hosts with Spanish Microsoft titles
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0af74-a6ab-7022-9baa-1a6ef2eb4eef/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0416 — Microsoft account (ES)

```text
https://yunk-frerink.alc.onl/
```

- **Domain:** `yunk-frerink.alc.onl`
- **Technique:** Spanish Microsoft sign-in clone on alc.onl
- **Detection:** alc.onl subdomains titled 'Iniciar sesión en tu cuenta Microsoft'
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0af76-f72b-74ee-9a5e-e83562cae8f0/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0417 — Microsoft account

```text
https://signin.broker/E.SFfn0JUJ9O3uu4oG1Q
```

- **Domain:** `signin.broker`
- **Technique:** Same /E.<token> infrastructure as authentication.ms and multi-factor.link; a sibling URL decodes to a Hoxhunt simulation string, so this may be training infrastructure
- **Detection:** Check whether the domain is on your security-awareness vendor's allowlist before blocking; match /E.[A-Za-z0-9_-]+
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0c6a2-248b-7554-a6c1-a66ff189ec24/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0418 — Microsoft account (E.ON lure)

```text
http://gsd.eon-account.com/E.Oq1q8gPNJYc
```

- **Domain:** `gsd.eon-account.com`
- **Technique:** /E.<token> kit on an E.ON-lookalike domain; possibly phishing-simulation infrastructure
- **Detection:** Match /E.<token> on brand-lookalike *-account.com domains
- **Source:** OpenPhish (via urlscan.io) — https://urlscan.io/result/01a0c40f-e5e2-73c9-b674-394a4cec65d0/
- **Status:** active
- **First seen:** 2026-09-21

### mfs-0419 — Microsoft SharePoint

```text
https://almaghrabifactory-com.ae-sharepoint.com/
```

- **Domain:** `almaghrabifactory-com.ae-sharepoint.com`
- **Technique:** Typosquat domain ae-sharepoint.com with per-target company subdomains ('Sharepoint Secure Panel'), 0 days old
- **Detection:** Block *.ae-sharepoint.com; hunt CT logs for <company>-<tld>.<x>-sharepoint.com
- **Source:** urlscan.io certstream-suspicious — https://urlscan.io/result/01a0c83d-892b-73eb-b9b2-8b7fbf9eacf9/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0420 — Microsoft SharePoint

```text
https://unisusgroups.ae-sharepoint.com/
```

- **Domain:** `unisusgroups.ae-sharepoint.com`
- **Technique:** Per-target subdomain that redirects to sharepointdocument-verification.com ('SharePoint — Documents')
- **Detection:** Block the sharepointdocument-verification.com domain
- **Source:** urlscan.io certstream-suspicious — https://urlscan.io/result/01a0c878-1075-74bb-b877-77d2aeed2fe7/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0421 — Microsoft 365

```text
https://vendnue.com/auth
```

- **Domain:** `vendnue.com`
- **Technique:** 0-day-old domain serving a cloned Entra ID 'Sign in to your account' page at /auth
- **Detection:** Domains under 7 days old with Microsoft login titles that are not in Microsoft ASNs
- **Source:** urlscan.io — https://urlscan.io/result/01a0c5e5-6f65-74ef-9486-404ece190d13/
- **Status:** active
- **First seen:** 2026-09-21

### mfs-0422 — Microsoft 365

```text
https://koukgruop.com/
```

- **Domain:** `koukgruop.com`
- **Technique:** 0-day-old typo domain ('gruop') hosting a Microsoft sign-in clone
- **Detection:** CT-log hunting for 'gruop' misspellings plus Microsoft login titles
- **Source:** urlscan.io — https://urlscan.io/result/01a0c2eb-9ec6-74aa-9b20-116ee7cc23a7/
- **Status:** active
- **First seen:** 2026-09-21

### mfs-0423 — Microsoft 365

```text
https://docsviewer.online/
```

- **Domain:** `docsviewer.online`
- **Technique:** Document-viewer themed 0-day domain serving a Microsoft sign-in clone
- **Detection:** 'docs'/'viewer' new domains titled 'Sign in to your account'
- **Source:** urlscan.io — https://urlscan.io/result/01a0b7fd-2049-711b-8bf8-030bfc2b8e2c/
- **Status:** active
- **First seen:** 2026-09-19

### mfs-0424 — Microsoft 365

```text
https://awesomejobfonts.top/
```

- **Domain:** `awesomejobfonts.top`
- **Technique:** 0-day .top domain hosting a Microsoft sign-in clone
- **Detection:** New .top domains with Microsoft login page titles
- **Source:** urlscan.io — https://urlscan.io/result/01a0ad04-840c-7137-a6a7-743f5545ac83/
- **Status:** active
- **First seen:** 2026-09-17

### mfs-0425 — Outlook / Microsoft 365

```text
https://f005.backblazeb2.com/file/jamunaban/myoffice.html
```

- **Domain:** `f005.backblazeb2.com`
- **Technique:** Credential-harvest page hosted on Backblaze B2 cloud storage (abuse of trusted cloud storage)
- **Detection:** Flag f00*.backblazeb2.com/file/*/myoffice.html and HTML pages titled 'Outlook' served from B2 buckets
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0426 — Microsoft 365 / Entra ID

```text
https://microsoft-0r.github.io/Microsoft.net/
```

- **Domain:** `microsoft-0r.github.io`
- **Technique:** Cloned 'Sign in to your account' AAD page on GitHub Pages, loads aadcdn assets
- **Detection:** Hunt *.github.io pages titled 'Sign in to your account' that reference aadcdn.msftauth.net or login.microsoftonline
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0427 — Outlook Web App

```text
http://owa.goldensemolina.com.tr/
```

- **Domain:** `owa.goldensemolina.com.tr`
- **Technique:** OWA login clone on a compromised or lookalike 'owa.' subdomain
- **Detection:** Alert on 'owa.' subdomains outside your own tenant domains serving pages titled 'Outlook'
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0428 — Microsoft 365

```text
https://security-server-landing-page--james2606.replit.app/
```

- **Domain:** `security-server-landing-page--james2606.replit.app`
- **Technique:** Replit-hosted 'security-server-landing-page' kit cloning the Microsoft sign-in page
- **Detection:** Block the regex security-server-(landing-)?page--*.replit.app, which is a recurring Microsoft phishing kit pattern
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0429 — Microsoft 365 / Outlook

```text
https://cgi.s-ed1.cloud.gcore.lu/O365.html
```

- **Domain:** `cgi.s-ed1.cloud.gcore.lu`
- **Technique:** Base64 + nested unescape-obfuscated 'Microsoft | Login' page on Gcore object storage
- **Detection:** Flag *.cloud.gcore.lu HTML pages that use atob() and document.write(unescape()); the filename O365.html is a strong signal
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0430 — Microsoft Teams / Microsoft 365

```text
http://s.teams-tb.com/p/fjbd-cbch/wevgmaqp
```

- **Domain:** `s.teams-tb.com`
- **Technique:** Teams-lookalike domain using the same /p/fjbd-cbch/ path kit as teams-ra.com
- **Detection:** Hunt newly registered teams-??.com domains and URLs matching /p/fjbd-cb[a-z]{2}/[a-z]{8}
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0431 — Microsoft Teams / Microsoft 365

```text
http://teams-lo.com/p/fjbd-cbcr/xlxwgqxa
```

- **Domain:** `teams-lo.com`
- **Technique:** Teams-lookalike typosquat domain from the same /p/fjbd-* campaign
- **Detection:** Hunt newly registered teams-??.com domains and URLs matching /p/fjbd-cb[a-z]{2}/[a-z]{8}
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0432 — Microsoft 365

```text
https://www.the365notify.com/AccountSelectionPage/c
```

- **Domain:** `www.the365notify.com`
- **Technique:** Lookalike '365' domain hosting a cloned Microsoft 'Sign in to your account' account-picker page
- **Detection:** Flag newly registered domains containing '365'/'notify' that serve pages titled 'Sign in to your account' with the path /AccountSelectionPage/
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0433 — Microsoft 365 / Outlook

```text
http://security-server-landing-page--peterajiri2000.replit.app/
```

- **Domain:** `security-server-landing-page--peterajiri2000.replit.app`
- **Technique:** Microsoft login clone on Replit free hosting, part of the recurring 'security-server-landing-page--<user>' kit
- **Detection:** Hunt for *.replit.app hosts matching security-server-(landing-)?page--* that load aadcdn/msftauth assets
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0434 — Microsoft Account

```text
https://scsproyectos.cl/bx/bell.html
```

- **Domain:** `scsproyectos.cl`
- **Technique:** Compromised .cl website hosting a static HTML 'Security verification - Microsoft account' credential page
- **Detection:** Alert on HTML pages outside Microsoft domains titled 'Security verification - Microsoft account'
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0435 — Microsoft Account (DocuSign lure)

```text
http://pizzlelinchy.s3.us-east-1.amazonaws.com/DoSignDocu-Project.html
```

- **Domain:** `pizzlelinchy.s3.us-east-1.amazonaws.com`
- **Technique:** Phishing page on an AWS S3 bucket using a DocuSign-themed file name to lead to Microsoft account verification
- **Detection:** Block s3.amazonaws.com objects with DocuSign/DoSign names that contain Microsoft sign-in branding
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0436 — Hotmail / Microsoft 365

```text
https://hotmail365new.s3.ap-northeast-1.amazonaws.com/MicroUpdateaccount-security.html
```

- **Domain:** `hotmail365new.s3.ap-northeast-1.amazonaws.com`
- **Technique:** Hotmail account-security update lure hosted on an AWS S3 bucket
- **Detection:** Flag S3 bucket names containing hotmail/365/office and HTML objects named *account-security*
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0437 — Microsoft Office 365

```text
https://f005.backblazeb2.com/file/kingshit66/myoffice.html
```

- **Domain:** `f005.backblazeb2.com`
- **Technique:** Office 365 login page on Backblaze B2 storage, the same 'myoffice.html' kit as the jamunaban bucket
- **Detection:** Hunt for f00*.backblazeb2.com/file/*/myoffice.html across all bucket names
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0438 — Microsoft Excel / Office 365

```text
https://accounts-ba666e1a.jkhjkjk.workers.dev/ba666e1a43c4497a
```

- **Domain:** `accounts-ba666e1a.jkhjkjk.workers.dev`
- **Technique:** Fake 'Excel - Shared Document' credential page on Cloudflare Workers
- **Detection:** Flag workers.dev hosts starting with 'accounts-' that serve pages titled 'Excel - Shared Document'
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0439 — Microsoft 365 / Entra ID

```text
https://wildlands.acltci.com/login?method=signin&mode=secure&client_id=4765445b-32c6-49b0-83e6-1d93765276ca&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Flogin.microsoftonline.com%2F
```

- **Domain:** `wildlands.acltci.com`
- **Technique:** Credential harvester on a compromised legitimate host, faking an OAuth authorize request with a capital-I 'redirect_urI' parameter pointing at login.microsoftonline.com
- **Detection:** Proxy/URL hunt for query strings containing 'redirect_urI' (capital i) or 'sso_reload=true' on non-Microsoft hostnames — the real parameter is 'redirect_uri' and only appears on login.microsoftonline.com
- **Source:** OpenPhish + PhishTank (via phishunt.io) — https://phishunt.io/source/phishtank/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0440 — Microsoft Outlook / Live

```text
http://validar-micuenta-outlook.yzz.me
```

- **Domain:** `validar-micuenta-outlook.yzz.me`
- **Technique:** Spanish-language 'validar mi cuenta' Outlook account-verification typosquat hosted on the free yzz.me subdomain service over plain HTTP
- **Detection:** Alert on DNS/HTTP to *.yzz.me and on newly seen hostnames combining Spanish verbs (validar, verificar, reactivar, acceso) with outlook/hotmail/microsoft
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0441 — Microsoft 365

```text
https://authentication.ms/E.bNNF6nWCtxqGCg?/confirm/verify
```

- **Domain:** `authentication.ms`
- **Technique:** Brandjacked .ms domain masquerading as a Microsoft authentication endpoint; per-victim 'E.<token>' path serves an MFA/confirm-identity credential prompt
- **Detection:** Block the apex domain authentication.ms and hunt for URI paths matching the regex /E\.[A-Za-z0-9_-]{12,}/ across authentication.ms, multi-factor.link, auth.properties and signin.broker
- **Source:** OpenPhish public feed — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0442 — Microsoft Outlook / Office 365

```text
https://publicofficeoutlooknotificationscry-dpkjhfszqaa2.edgeone.dev/
```

- **Domain:** `publicofficeoutlooknotificationscry-dpkjhfszqaa2.edgeone.dev`
- **Technique:** Outlook 'notification' credential page on Tencent EdgeOne Pages free hosting, using a long keyword-stuffed label plus random suffix to defeat string blocklists
- **Detection:** Treat *.edgeone.dev as an unsanctioned hosting provider (same class as *.pages.dev / *.workers.dev); flag labels >40 chars that concatenate office/outlook/notification keywords before a random 12-char suffix
- **Source:** OpenPhish public feed — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0443 — Microsoft 365

```text
https://security-server-page--sheryln1990.replit.app/
```

- **Domain:** `security-server-page--sheryln1990.replit.app`
- **Technique:** Replit-hosted 'security server' fake sign-in kit; the --<operator> suffix is the attacker's Replit account name, so each actor mass-produces near-identical pages
- **Detection:** Regex the proxy logs for ^https?://(security-server|server-security)[a-z-]*--[a-z0-9-]+\.replit\.app — the kit name is stable while the operator handle rotates
- **Source:** OpenPhish public feed — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0444 — Microsoft 365

```text
https://security-server--tabbielynn.replit.app/
```

- **Domain:** `security-server--tabbielynn.replit.app`
- **Technique:** Same Replit 'security-server' Microsoft sign-in kit under a different operator handle
- **Detection:** Block *.replit.app wholesale if unused, or alert on any Replit app whose HTML references login.microsoftonline.com assets or aadcdn.msftauth.net
- **Source:** OpenPhish public feed — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0445 — Microsoft 365

```text
https://security-server-page--servarog.replit.app/
```

- **Domain:** `security-server-page--servarog.replit.app`
- **Technique:** Replit 'security-server-page' variant of the same Microsoft credential-harvest kit
- **Detection:** Pivot on favicon/HTML hash of one confirmed security-server--* page in urlscan.io to enumerate the rest of the cluster before they are reported
- **Source:** OpenPhish public feed — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0446 — Microsoft 365

```text
https://microsoft0117.vercel.app
```

- **Domain:** `microsoft0117.vercel.app`
- **Technique:** Free-hosting abuse — credential-harvest page on attacker-created Vercel subdomain; page title is literally "Microsoft"
- **Detection:** Alert on outbound HTTPS to *.vercel.app subdomains containing 'microsoft'/'office'/'outlook' tokens; these are never Microsoft-owned
- **Source:** OpenPhish / phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0447 — Microsoft OneDrive

```text
http://creyt.cl/centennialcws/onedrive-verify-obf.html
```

- **Domain:** `creyt.cl`
- **Technique:** Compromised legitimate site hosting the reused 'onedrive-verify-obf' obfuscated HTML credential kit
- **Detection:** Hunt proxy/web logs for any URI path ending in 'onedrive-verify-obf.html' — a fixed kit filename reused across many hacked hosts
- **Source:** OpenPhish / phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0448 — Microsoft 365 / Outlook Web

```text
https://clovdmicrsotfmailaamkagmxn2uxywe.klassik-erh.de
```

- **Domain:** `clovdmicrsotfmailaamkagmxn2uxywe.klassik-erh.de`
- **Technique:** Subdomain squatting on a compromised German domain; label is misspelled 'clovd-micrsotf-mail' plus random hex padding
- **Detection:** Flag DNS for long (>30 char) single-label subdomains mixing a misspelled 'microsoft'/'micrsotf' string with random alphanumerics under unrelated TLDs
- **Source:** OpenPhish / phishunt.io — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0449 — Microsoft 365 (login.microsoftonline.com)

```text
https://microsoft-online.gr
```

- **Domain:** `microsoft-online.gr`
- **Technique:** Typosquat of 'microsoftonline' with an inserted hyphen on a .gr ccTLD
- **Detection:** Regex newly-registered-domain feeds for /micro-?soft-?online/ on any TLD outside microsoft.com's registered set
- **Source:** OpenPhish / phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0450 — Microsoft Office 365

```text
https://microsoftoffice-o365.com
```

- **Domain:** `microsoftoffice-o365.com`
- **Technique:** Brand-concatenation typosquat ('microsoftoffice' + 'o365') used as a sign-in lure domain
- **Detection:** Alert on domains combining two Microsoft brand tokens (microsoft/office/o365/m365) joined by a hyphen — Microsoft does not register these patterns
- **Source:** OpenPhish / phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0451 — Microsoft Teams

```text
http://www.miccrossofteam.top/
```

- **Domain:** `www.miccrossofteam.top`
- **Technique:** Homoglyph/typosquat ('miccrossofteam' = Microsoft Teams) on a cheap .top TLD, served over plain HTTP
- **Detection:** Fuzzy-match (Levenshtein <=3) registered domains against 'microsoftteams'; prioritize .top/.xyz/.cfd TLDs and HTTP-only listeners
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0452 — Microsoft Outlook / Live

```text
http://www.connexioncompteoutlook.weebly.com/
```

- **Domain:** `www.connexioncompteoutlook.weebly.com`
- **Technique:** Weebly free-site abuse with a French-language lure ('connexion compte Outlook' = Outlook account sign-in)
- **Detection:** Block/alert on *.weebly.com and *.weeblysite.com hostnames whose label contains outlook/hotmail/microsoft/office — a persistently abused free-hosting pattern
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0453 — Microsoft 365 / Outlook

```text
https://verificarcuenta-micros0ft2026way.zya.me/?i=1
```

- **Domain:** `verificarcuenta-micros0ft2026way.zya.me`
- **Technique:** Spanish-language 'verify your account' credential-harvest page on free zya.me subdomain host, homoglyph 'micros0ft'
- **Detection:** Alert on outbound HTTP POST to *.zya.me / *.yzz.me / *.hstn.me — free ByetHost-family hosts have no legitimate enterprise use
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0454 — Microsoft 365

```text
https://microsoft-office365.site
```

- **Domain:** `microsoft-office365.site`
- **Technique:** Typosquat brand-in-domain-label credential page behind Cloudflare; flagged young domain
- **Detection:** Hunt newly-registered .site/.online/.live TLDs containing 'microsoft'+'office365' in CT logs; block at DNS before first click
- **Source:** Google Safe Browsing (via phishunt.io) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0455 — Microsoft Teams

```text
https://microsoftsteam.live
```

- **Domain:** `microsoftsteam.live`
- **Technique:** Typosquat of 'microsoft teams' (dropped space/letter shuffle) serving fake Teams/M365 sign-in
- **Detection:** Regex edit-distance <=2 against 'microsoftteams' on newly observed domains in proxy logs
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0456 — Microsoft Forms / Microsoft 365

```text
https://forms-microsoft.com
```

- **Domain:** `forms-microsoft.com`
- **Technique:** Microsoft Forms-themed lure domain redirecting to cloned Entra ID sign-in
- **Detection:** Any hostname matching ^(forms|inbox|protect|urgent|salessupport)-microsoft\. is not Microsoft — Microsoft Forms only lives on forms.office.com / forms.cloud.microsoft
- **Source:** Google Safe Browsing (via phishunt.io) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0457 — Microsoft Teams

```text
https://microsofteams-setup.com
```

- **Domain:** `microsofteams-setup.com`
- **Technique:** Fake 'Teams setup/installer' page pivoting to M365 credential prompt
- **Detection:** Block domains combining a Microsoft product name with setup/download/update tokens; real Teams installers come from statics.teams.cdn.office.net
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0459 — Microsoft 365 / Entra ID

```text
https://login-microsoft-verify.online
```

- **Domain:** `login-microsoft-verify.online`
- **Technique:** Typosquat sign-in-verification lure, newly registered lookalike
- **Detection:** CT-log monitor for certs with SAN containing 'login'+'microsoft'+'verify'; legitimate Microsoft sign-in is only login.microsoftonline.com
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0460 — Microsoft Account / Live

```text
https://microsoft-account.live
```

- **Domain:** `microsoft-account.live`
- **Technique:** Typosquat of account.live.com using .live TLD as the brand suffix
- **Detection:** Flag domains where a Microsoft service name is the SLD and the TLD mimics the real hostname's subdomain (account.live.com vs microsoft-account.live)
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0461 — Microsoft 365 / passkey

```text
https://microsoft-key.online
```

- **Domain:** `microsoft-key.online`
- **Technique:** Passkey/security-key registration lure — same theme as the Storm-3121/Storm-3032 passkey cluster
- **Detection:** Extend existing passkey-phish blocklist regex to (passkey|key|mfa|sso)-?(microsoft|os)\.(com|online|live)
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0462 — Microsoft 365 / Office 365

```text
https://office365plus.net
```

- **Domain:** `office365plus.net`
- **Technique:** Brand-plus-suffix typosquat landing page for OWA credential capture
- **Detection:** Block newly-registered domains prefixed 'office365' outside microsoft.com/office.com zones
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0463 — Microsoft Teams

```text
https://microsofteamsinvite.top
```

- **Domain:** `microsofteamsinvite.top`
- **Technique:** Fake Teams meeting-invite lure leading to M365 sign-in page (same pattern as msteamsinvitees.com)
- **Detection:** Hunt 'teams*invite*' domains in mail URL-rewrite logs; real invites resolve to teams.microsoft.com / teams.live.com
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0464 — Hotmail / Outlook

```text
https://hotmailli.site
```

- **Domain:** `hotmailli.site`
- **Technique:** Hotmail typosquat on cheap .site TLD
- **Detection:** Alert on any non-microsoft.com/live.com domain whose page title contains 'Hotmail' or 'Outlook' sign-in strings
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-28

### mfs-0465 — Outlook / Microsoft 365

```text
https://outlookinboxmessage.com
```

- **Domain:** `outlookinboxmessage.com`
- **Technique:** 'New message in your inbox' notification lure to fake OWA logon
- **Detection:** Block domains concatenating outlook+inbox/message/mail tokens; correlate with inbound mail subjects referencing undelivered messages
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-27

### mfs-0466 — Microsoft Teams

```text
https://microsofteamsinvite.live
```

- **Domain:** `microsofteamsinvite.live`
- **Technique:** Teams invite typosquat, sibling of microsofteamsinvite.top on the same registration burst
- **Detection:** Cluster-block the whole microsofteamsinvite.* family across TLDs
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-27

### mfs-0467 — Microsoft Teams

```text
https://teams-microsofts-meet.com
```

- **Domain:** `teams-microsofts-meet.com`
- **Technique:** Pluralized-brand typosquat ('microsofts') fake Teams meeting join page
- **Detection:** Detect plural/possessive brand mutations: microsofts, microsoftt, micosoft in proxy SNI
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0468 — Microsoft Teams

```text
https://teams-microsoft-downloads.com
```

- **Domain:** `teams-microsoft-downloads.com`
- **Technique:** Fake Teams download page (variant of the known teams-microsoft-download.com)
- **Detection:** Already-known sibling teams-microsoft-download.com — block the singular/plural pair together
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0469 — Outlook

```text
https://outlook.surf
```

- **Domain:** `outlook.surf`
- **Technique:** Bare-brand squat on a low-reputation TLD used for webmail credential pages
- **Detection:** Deny-list bare Microsoft product names on non-Microsoft TLDs (.surf, .sbs, .cfd, .shop, .day, .baby)
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0470 — OneDrive / SharePoint

```text
https://onedriveshare.net
```

- **Domain:** `onedriveshare.net`
- **Technique:** Fake 'shared document' OneDrive lure fronting an M365 sign-in prompt
- **Detection:** OneDrive sharing only occurs on *.sharepoint.com / 1drv.ms / onedrive.live.com — alert on any other host serving a OneDrive-branded document viewer
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0471 — OneDrive

```text
https://onedrivecloud.net
```

- **Domain:** `onedrivecloud.net`
- **Technique:** OneDrive brand-plus-suffix squat registered in the same batch as onedriveshare.net
- **Detection:** Same registrar/nameserver pivot as onedriveshare.net — block the pair and monitor the hosting ASN
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0472 — Microsoft / Windows

```text
https://microsoft-windows-support.com
```

- **Domain:** `microsoft-windows-support.com`
- **Technique:** Tech-support-themed lure escalating to Microsoft account sign-in
- **Detection:** Pair with existing microsoft-techsupport.com blocks; flag any 'support'+'microsoft' domain not under support.microsoft.com
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0473 — OneDrive / Microsoft 365

```text
https://microsoft-onedrive.org
```

- **Domain:** `microsoft-onedrive.org`
- **Technique:** Hyphenated brand-pair typosquat hosting a OneDrive document-access sign-in
- **Detection:** Regex ^microsoft-(onedrive|sharepoint|teams|office)\. across all TLDs — none are Microsoft-owned
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0474 — Outlook / Microsoft 365

```text
https://inbox-microsoft.com
```

- **Domain:** `inbox-microsoft.com`
- **Technique:** Mailbox-notification lure domain for OWA credential capture
- **Detection:** Match ^(inbox|mail|webmail)-microsoft\. in SNI/DNS; no legitimate Microsoft mail host uses that form
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0475 — OneDrive

```text
https://0nedrive.space
```

- **Domain:** `0nedrive.space`
- **Technique:** Homoglyph typosquat (zero-for-O) OneDrive file-share phishing page
- **Detection:** Normalize 0→o and 1→l on observed domains before comparing to a Microsoft brand list; catches 0utl00k/0nedrive families
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-26

### mfs-0476 — Microsoft 365

```text
https://salessupport-microsoft.com
```

- **Domain:** `salessupport-microsoft.com`
- **Technique:** Fake Microsoft sales/support contact page routing to an Entra ID credential prompt
- **Detection:** Any hostname ending '-microsoft.com' is a squat — the real zone is microsoft.com with brand as the SLD
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0477 — Outlook / Microsoft Defender

```text
https://protect-outlook.com
```

- **Domain:** `protect-outlook.com`
- **Technique:** 'Protect your mailbox' security-alert lure to fake Outlook sign-in
- **Detection:** Correlate DNS hits with inbound mail containing 'unusual sign-in activity' subject lines
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0478 — Outlook Web Access

```text
https://outlookaccessportal.com
```

- **Domain:** `outlookaccessportal.com`
- **Technique:** Fake OWA 'access portal' credential-harvest page
- **Detection:** Hunt POSTs to hosts with 'portal'+'outlook'/'owa' tokens; legitimate OWA is outlook.office.com / outlook.office365.com
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0479 — OneDrive

```text
https://com-onedrive.com
```

- **Domain:** `com-onedrive.com`
- **Technique:** Reversed-label squat designed to read as 'onedrive.com' in truncated mobile URL bars
- **Detection:** Flag domains beginning 'com-' — a classic mobile URL-bar truncation trick; sibling of known com-onedrive-microsoftonline.com
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0480 — Outlook / Microsoft Account

```text
https://accountrecovery-outlook.com
```

- **Domain:** `accountrecovery-outlook.com`
- **Technique:** Account-recovery lure harvesting credentials plus recovery email/phone for MFA reset
- **Detection:** Alert on 'recovery'/'reset' + Microsoft brand domains; real recovery is account.live.com/acsr
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0481 — Microsoft 365 / Entra ID

```text
https://m365-login-microsoft.com
```

- **Domain:** `m365-login-microsoft.com`
- **Technique:** Direct login-page typosquat (m365 + login + microsoft tokens)
- **Detection:** Highest-priority pattern: any domain containing both 'login' and 'microsoft' that is not login.microsoftonline.com or login.microsoft.com
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0482 — Microsoft 365 / Entra ID

```text
https://microsoft-security.online
```

- **Domain:** `microsoft-security.online`
- **Technique:** Security-alert lure domain for MFA/passkey re-enrollment social engineering
- **Detection:** Same lure family as the Storm-3121 passkey cluster — watch for target company name inserted as a subdomain (contoso.microsoft-security.online)
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0483 — OneDrive / SharePoint

```text
https://onedrive-mysharepoint.com
```

- **Domain:** `onedrive-mysharepoint.com`
- **Technique:** Combined OneDrive+SharePoint squat mimicking the real *-my.sharepoint.com personal-site hostname
- **Detection:** Match 'mysharepoint' as a single label — the genuine form is tenant-my.sharepoint.com with 'my' as its own label
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0484 — Microsoft 365 / Entra ID

```text
https://mylogin-microsoftonline.com
```

- **Domain:** `mylogin-microsoftonline.com`
- **Technique:** Near-exact typosquat of login.microsoftonline.com with 'my' prefix
- **Detection:** Deny any registrable domain containing 'microsoftonline' — Microsoft owns only microsoftonline.com itself
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0485 — Microsoft 365 / OneDrive

```text
https://ms365-onedrive.com
```

- **Domain:** `ms365-onedrive.com`
- **Technique:** Abbreviation squat (ms365) hosting OneDrive document-share credential page
- **Detection:** Add 'ms365','m365','o365' abbreviations to brand-token lists — most detection rules only match the full 'microsoft' string
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0486 — Microsoft 365 / Outlook

```text
https://accounts-login-micr0s0ft-mailsetup.com
```

- **Domain:** `accounts-login-micr0s0ft-mailsetup.com`
- **Technique:** Homoglyph (micr0s0ft) mail-setup lure, long multi-token domain to defeat substring rules
- **Detection:** Apply leetspeak normalization (0→o, 1→l, 5→s) before brand matching; this domain is invisible to a plain 'microsoft' grep
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0487 — Microsoft 365

```text
https://myaccount-microsoft365.com
```

- **Domain:** `myaccount-microsoft365.com`
- **Technique:** Fake 'My Account' portal squat of myaccount.microsoft.com
- **Detection:** Compare against the real myaccount.microsoft.com; alert when the brand appears after a hyphen rather than as the registrable domain
- **Source:** phishunt.io (CT logs) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0488 — Microsoft Outlook / Microsoft 365

```text
http://outlook.evergreenfin.ltd
```

- **Domain:** `outlook.evergreenfin.ltd`
- **Technique:** Subdomain of an active phishing estate (evergreenfin.ltd) serving a fake Outlook/OWA sign-in page
- **Detection:** Hunt for any DNS/proxy resolution to *.evergreenfin.ltd — the same estate already hosts office., onelogin. and xn--knto-55d. subdomains; block the apex, not individual hosts
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0489 — Microsoft 365 / Office 365

```text
https://micr0s0ft0ffice365.com
```

- **Domain:** `micr0s0ft0ffice365.com`
- **Technique:** Homoglyph typosquat (zero-for-o) of 'microsoftoffice365' hosting a credential-harvest sign-in clone
- **Detection:** Regex outbound HTTP Host and email links for microsoft/office brand strings containing digits 0/1 substituted for o/l
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0490 — Microsoft Entra ID / login.microsoftonline.com

```text
https://microsoftonlinesm.top
```

- **Domain:** `microsoftonlinesm.top`
- **Technique:** Typosquat of login.microsoftonline.com on a low-cost .top TLD
- **Detection:** Alert on any resolved domain containing 'microsoftonline' that is not *.microsoftonline.com; flag .top/.xyz/.sbs TLDs registered <30 days
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0491 — Microsoft OneDrive

```text
https://com-microsoft-onedrive.live
```

- **Domain:** `com-microsoft-onedrive.live`
- **Technique:** Reversed-label typosquat ('com-' prefix) mimicking a OneDrive share notification landing page
- **Detection:** Flag hostnames that begin with 'com-' or 'www-' followed by a brand token — a reliable reversed-FQDN squat signal
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0492 — Microsoft Outlook

```text
https://outlookk.site
```

- **Domain:** `outlookk.site`
- **Technique:** Doubled-character typosquat of 'outlook' on a cheap .site TLD
- **Detection:** Levenshtein distance <=2 against 'outlook'/'microsoft'/'onedrive' over newly observed domains in proxy logs
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0493 — Microsoft Outlook / OWA

```text
https://outlook-email-primecaretech.com
```

- **Domain:** `outlook-email-primecaretech.com`
- **Technique:** Target-tailored webmail lure — victim org name appended to 'outlook-email-' for a bespoke OWA sign-in clone
- **Detection:** Hunt registrations matching ^(outlook|owa|mail)-.*-?<yourcompany> — set a CT-log watch on your own brand name paired with Microsoft tokens
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0494 — Microsoft 365 / OneDrive

```text
https://microsoftfile.xyz
```

- **Domain:** `microsoftfile.xyz`
- **Technique:** Brand-squat document-share lure funnelling to a Microsoft credential prompt
- **Detection:** Block newly registered .xyz/.top domains containing 'microsoft' at the egress proxy by default
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0495 — Microsoft 365

```text
https://microsoftpro.top
```

- **Domain:** `microsoftpro.top`
- **Technique:** Exact-brand-plus-suffix squat on .top TLD
- **Detection:** Domain age <7 days + exact 'microsoft' substring + non-Microsoft registrar = auto-block candidate
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0496 — Microsoft 365

```text
https://microsoftplus.com
```

- **Domain:** `microsoftplus.com`
- **Technique:** Brand-plus-word squat used as an account-services / sign-in landing page
- **Detection:** Watch CT logs for certificates issued to 'microsoft'+generic-suffix .com names not owned by Microsoft Corp
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-29

### mfs-0497 — Microsoft Entra ID / microsoftonline.com

```text
https://microsoftolnine.com
```

- **Domain:** `microsoftolnine.com`
- **Technique:** Character-transposition typosquat ('olnine' for 'online') of login.microsoftonline.com
- **Detection:** Run a transposition/bitsquat generator against 'microsoftonline' and preload the results into DNS RPZ
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0498 — Microsoft Entra ID

```text
https://microsoftentraconnect.com
```

- **Domain:** `microsoftentraconnect.com`
- **Technique:** Entra-themed brand squat impersonating an identity/SSO re-enrolment portal
- **Detection:** Alert on any non-Microsoft domain containing 'entra' — rare token, very low false-positive rate
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0499 — Microsoft Teams

```text
https://microsoftteamupdate.com
```

- **Domain:** `microsoftteamupdate.com`
- **Technique:** Teams 'update required' lure leading to a Microsoft sign-in prompt
- **Detection:** Flag domains combining 'teams'/'team' with update|setup|invite|download tokens registered in the last 30 days
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0500 — Microsoft Office 365

```text
https://microsoftofficeph.com
```

- **Domain:** `microsoftofficeph.com`
- **Technique:** Brand squat with regional suffix hosting an Office 365 credential page
- **Detection:** Match 'microsoftoffice' as a contiguous substring in any non-microsoft.com host
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0501 — Microsoft OneDrive

```text
https://0nedrive.online
```

- **Domain:** `0nedrive.online`
- **Technique:** Homoglyph typosquat (zero-for-O) of OneDrive — sibling of the already-tracked 0nedrive.space
- **Detection:** Normalise 0->o and 1->l in observed hostnames, then re-match against your brand list
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-25

### mfs-0502 — Microsoft Entra ID / microsoftonline.com

```text
https://microsoftidonline.com
```

- **Domain:** `microsoftidonline.com`
- **Technique:** Insertion typosquat of microsoftonline.com posing as the Microsoft identity sign-in host
- **Detection:** Any host matching microsoft.*online that is not *.microsoftonline.com should be blocked outright
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0503 — Microsoft 365

```text
https://microsoftprovider.com
```

- **Domain:** `microsoftprovider.com`
- **Technique:** Brand squat presented as a Microsoft service/support provider portal with a sign-in step
- **Detection:** CT-log monitor for new certs with CN containing 'microsoft' outside Microsoft's ASNs
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0504 — Microsoft 365 / OneDrive

```text
https://microsoftfileoffline.top
```

- **Domain:** `microsoftfileoffline.top`
- **Technique:** Fake 'offline file' share notification leading to a Microsoft credential prompt
- **Detection:** Combine 'microsoft'+file|doc|share tokens with .top/.sbs/.cfd TLDs for a high-signal block rule
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0505 — Microsoft Outlook

```text
https://outlook.day
```

- **Domain:** `outlook.day`
- **Technique:** Exact-brand squat on a novelty TLD, used for Outlook webmail sign-in lures
- **Detection:** Block exact label 'outlook'/'hotmail'/'onedrive' as an SLD under any TLD Microsoft does not own
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-24

### mfs-0506 — Microsoft OneDrive

```text
https://microsoftonedrivesync.top
```

- **Domain:** `microsoftonedrivesync.top`
- **Technique:** 'OneDrive sync error, re-authenticate' lure on a newly registered .top domain
- **Detection:** Alert on 'onedrive'+sync|verify|error|share token combinations in URL host or path
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0507 — Microsoft 365

```text
https://fra-microsoft.com
```

- **Domain:** `fra-microsoft.com`
- **Technique:** Region-prefixed brand squat ('fra-' = Frankfurt) — part of a three-TLD cluster registered the same day
- **Detection:** Pivot on registrant/NS for fra-microsoft.com/.info/.store; hunt other <region>-microsoft.* patterns
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0508 — Microsoft 365

```text
https://fra-microsoft.info
```

- **Domain:** `fra-microsoft.info`
- **Technique:** Region-prefixed brand squat, same-day cluster with fra-microsoft.com and fra-microsoft.store
- **Detection:** Block the whole fra-microsoft.* cluster; watch for new TLD siblings on the same nameservers
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0509 — Microsoft 365

```text
https://fra-microsoft.store
```

- **Domain:** `fra-microsoft.store`
- **Technique:** Region-prefixed brand squat, same-day cluster with fra-microsoft.com and fra-microsoft.info
- **Detection:** Same-day multi-TLD registration of an identical brand label is itself a strong phishing indicator — alert on it
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0510 — Microsoft Outlook / OWA

```text
https://axisurbanmobilityllc-outlook-company.com
```

- **Domain:** `axisurbanmobilityllc-outlook-company.com`
- **Technique:** Victim-specific BEC lure — target company name concatenated with 'outlook-company' for a tailored webmail sign-in
- **Detection:** CT-log watch on '<yourcompanyname>-outlook' and '<yourcompanyname>-microsoft' permutations
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0511 — Microsoft Outlook

```text
https://outlook.beer
```

- **Domain:** `outlook.beer`
- **Technique:** Exact-brand squat on a novelty TLD
- **Detection:** Maintain a deny-by-default rule for brand-exact SLDs on nTLDs (.beer, .baby, .surf, .day, .sbs)
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0512 — Microsoft Outlook

```text
https://outlook.baby
```

- **Domain:** `outlook.baby`
- **Technique:** Exact-brand squat on a novelty TLD, sibling registration to outlook.beer
- **Detection:** Pivot on the registrar/NS shared by outlook.beer and outlook.baby to surface the rest of the batch
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-23

### mfs-0513 — Microsoft 365

```text
https://urgent-microsoft.com
```

- **Domain:** `urgent-microsoft.com`
- **Technique:** Urgency-prefixed brand squat used for 'account will be suspended' credential-harvest pages
- **Detection:** Flag urgency tokens (urgent|alert|expire|suspend|verify|secure) adjacent to a Microsoft brand token
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0514 — Microsoft Teams

```text
https://teams-microsoft.cloud
```

- **Domain:** `teams-microsoft.cloud`
- **Technique:** Reversed brand-order squat on .cloud serving a Teams meeting/file lure into a Microsoft sign-in
- **Detection:** Match both orderings — 'teams-microsoft' and 'microsoft-teams' — outside microsoft.com/teams.microsoft.com
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0515 — Microsoft Teams

```text
https://microsoftteamssviewer.com
```

- **Domain:** `microsoftteamssviewer.com`
- **Technique:** Doubled-character typosquat ('teamss') posing as a Teams file viewer requiring sign-in
- **Detection:** Detect repeated-letter insertions in brand tokens (teamss, offfice, micrrosoft) via a squat generator feed
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0516 — Microsoft Outlook Web Access

```text
https://outlookwebupdate.com
```

- **Domain:** `outlookwebupdate.com`
- **Technique:** 'OWA update required' lure hosting an Outlook Web App sign-in clone
- **Detection:** Alert on outlook|owa combined with web|update|upgrade|migration tokens in newly seen domains
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0517 — Microsoft 365 / Outlook

```text
https://microsoft-messaging.com
```

- **Domain:** `microsoft-messaging.com`
- **Technique:** Brand squat framed as a Microsoft messaging/notification service with a credential gate
- **Detection:** Deny-list newly registered 'microsoft-<generic-noun>.com' patterns; Microsoft does not register these
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

### mfs-0518 — Microsoft 365

```text
https://microsoft08619.com
```

- **Domain:** `microsoft08619.com`
- **Technique:** Numeric-suffix brand squat — same disposable pattern as the previously tracked microsoft251207.com and 676132-microsoft.com
- **Detection:** Regex ^(microsoft|office|outlook)[0-9]{4,}\. or ^[0-9]{4,}-(microsoft|office)\. against DNS logs
- **Source:** phishunt.io newly registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-09-22

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["microsoft-advertising-authentification.sgn-1.com", "emanuelabsoluciones.com", "50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document.workers.dev", "aquaclaude-09494-9099403-docviewer.clear90489058903-document.workers.dev", "spx.pamconj.com", "login-microsoft-0nline.ts.r.appspot.com", "login-microsoft-outlook.el.r.appspot.com", "tlook-off365-signin.el.r.appspot.com", "xmaksvwq.wze.io", "noithatviet24h.vn", "newprojectdocument.uc.r.appspot.com", "onedrivelinkedindocument.oa.r.appspot.com", "spherical-door-277805.uc.r.appspot.com", "voicemail365.nn.r.appspot.com", "office365-portal-verify.el.r.appspot.com", "loginblxxslingfbvfgh600ohjm.ga", "proteccion-outlook2026.iceiy.com", "passkeyhelpdesk.com", "secure-passkey.com", "setupmypasskey.com", "add-passkey.com", "portalsetuphub.com", "microsoftonline-recovery.com", "0utl00k.online", "0utl00k.store", "0utl00k.site", "office365mail.com", "microsoft365online.cloud", "https-forms-cloud-microsoft-pages-responsepage-a.link", "onedrive-share.online", "contactsupport-microsoft.com", "helpsecure-microsoft.com", "676132-microsoft.com", "outlook10.net", "outlo0k.com", "onedrivee.online", "office365.internal-alerts.com", "support.m365-microsoft.com", "security.email-microsoft.com", "programme-hup.m365-microsoft.com", "security.m365-microsoft.com", "emailnotifications.m365-microsoft.com", "reactivar-microsoft-live.iceiy.com", "microsoftjk.eu.org", "microsoft-login-securitylogin.jimdofree.com", "click5.microsoftsupportcenter.digital", "click6.microsoftsupportcenter.digital", "microsoft-se.us", "microsoft.updata.net.cn", "microsoft.authorised-support.com", "microsoft365businessbasic.com", "office365licensingsupport.com", "microsoft365updates.com", "www-microsoft.com.cn", "microsoft-sharepoint.fr", "microsoftuk.co", "microsoft.vpn-update.org", "outlook-office365.com", "outlook.webaccess-alert.com", "outlook.verifytoken.com", "office365.rricrosoft-offices.org", "microsoft365licensingsupport.com", "onedrive.at-us.therelayservice.com", "outlookmail.social", "plugins.sugar-outlook.com", "hotmail143.net", "www.camisasdecolores.net", "www.owaexchange.com", "office-365-msn--oficeer.replit.app", "login.hotmails.info", "ctia-outlook-2026.s1.yapla.com", "deploypasskey.com", "passkeyadd.com", "login-microsoftonnline.jimdofree.com", "office.evergreenfin.ltd", "onelogin.evergreenfin.ltd", "msteamsinvitees.com", "msteamsinvitees.com", "msteamsinvitees.com", "moregoonsrue.com", "www.outlook-test.duckdns.org", "outlook-test.duckdns.org", "teams-microsoft-download.com", "onedrivedoc.cfd", "microsoftsteam.online", "microsoftapp.sbs", "microsoft365-techsupport.com", "microsoft-techsupport.com", "micros0ftsolutions.com", "info-microsoft.info", "gaming-outlook.com", "outlooksignal.com", "outlookemails.shop", "outlookdestinations.com", "microsoftteams.top", "microsoftenline.site", "microsoft-nextgenalpha-ai-private-asset-forum.com", "com-onedrive-microsoftonline.com", "management.daengrentacar.com", "konceptenterprises.com", "ccpipharma.com", "annastudios-paros.com", "hotelmidtownsurat.com", "dataclust.com", "cifutura.com", "hoaivt.com", "dronalms.com", "virextec.com", "offtic.com", "rootreseller.com", "management.michaelmarcotte.com", "kgsscans.com", "soil-management.com", "security-server-page--chisomotf.replit.app", "security-server-page--jhalskov68.replit.app", "www.teams-login.com", "outlook-email-2026.hstn.me", "intermezzoconsultoria.com.br", "soporte.offices-support.com", "soporte.offices-support.com", "ferdelmann.charles.office-share-microsoft.com", "www.ozatak.com", "security.m365-microsoft.com", "account-access-rc3uenqi.elitechiropracticandrehab.com", "chartered.flipbookonlinevault.com", "verificacion365.freepage.cc", "mxoff-standard-v.us-iad-10.linodeobjects.com", "login-microsoftonline.pl", "account-access-thlwvhxo.cxxzf.com", "account-access-unlcjkmj.androidpreneur.com", "saml-access-bgzdiwai.pelicol.com", "saml-access-hjg5zb1m.schuelerhvac.com", "saml-access-fgphrx1b.geefjelevenkleur.com", "saml-access-0yni8zkk.deltarstar.com", "saml-access-qhtexulk.atomzilla.com", "saml-access-ebntirhn.followmyitems.com", "saml-access-umjn1zxd.vnamecard.com", "saml-access-whwhikxl.lygdhc.com", "saml-access-4ejlnged.cciwedding.com", "saml-access-vdjnpebo.alltoyotatrucksuvparts.com", "onestep-access-aosbgdan.tv-appspot.com", "signin-access-3qbuumoo.alltoyotatrucksuvparts.com", "session-access-hrh9axw6.androidpreneur.com", "signin-access-ltcpr2s7.breakingpandora.com", "secure-access-ht0ysxlq.alltoyotatrucksuvparts.com", "verify-access-umjlvvrx.alltoyotatrucksuvparts.com", "signin-access-bpbippyw.geefjelevenkleur.com", "mfa-access-pyvxbnjc.atomzilla.com", "signin-access-whtc5iq4.accudiodesign.com", "authenticate-access-unb5gtsf.xhscyp.com", "validate-access-kgcdauwc.xhscyp.com", "verify-access-6dlrv01r.adogabroad.com", "identity-access-1w2m8s2x.arlingtonhousecleaning.com", "flipbookviewer.us", "authentication.ms", "microsoft.authorised-support.com", "microsoft.authorised-support.com", "chartered.flipbookonlinevault.com", "msoft-common-gbz-8999.us-sea-1.linodeobjects.com", "chartered.flipbookonlinevault.com", "connectezvousamicrosoftoutlook.weebly.com", "auth.properties", "multi-factor.link", "multi-factor.link", "authentication.ms", "m365-online.ch", "moripartnerch-365-mso-drive-auth9287364.cloud-storage-id0384723.workers.dev", "xn--knto-55d.evergreenfin.ltd", "s.teams-ra.com", "adi-panwar.github.io", "nk2184.craftum.io", "bnimail-owa.vercel.app", "security-server-landing-page--lme85959.replit.app", "security-server-landing-page--spencer-hunt1.replit.app", "teamliftss.com", "bx.wsapbfy.net", "comunidad--comunidadunitec.replit.app", "penielpeters44-spec.github.io", "security-server-page--emekemine206.replit.app", "security-server-landing-page--mariodrichard.replit.app", "roechling.site", "security-server-landing-page--microsoftdou.replit.app", "security-server-page--delta2rolspan.replit.app", "security-server-page--heainjus1.replit.app", "security-server-website--resultbox63.replit.app", "security-server--eplkaasi.replit.app", "security-server-landing-page--chriswazza79.replit.app", "security-server-landing-page--mauricemslatter.replit.app", "security-server-landing-page--retrobob.replit.app", "security-server-landing-page--aghnakazmi.replit.app", "security-server-static-page--raymondhug.replit.app", "server-security-landing-page--docu-sign.replit.app", "docusignfile-review-security-page--newstoolin.replit.app", "secure-html-editor--bradleyevans200.replit.app", "mail-us-exg07-exgh0st-0wa.replit.app", "ed-art-page.replit.app", "my-html-app-production-wsufv2.laravel.cloud", "fls-a2c06490-fc61-4ef8-95a7-68d9b72fbce7.laravel.cloud", "usc1.contabostorage.com", "usc1.contabostorage.com", "light.s-drc2.cloud.gcore.lu", "paymob.shop", "lobologisticgroup.com.mx", "www.kkms.lobologisticgroup.com.mx", "subseguirias.xyz", "channelhub.online", "zyexx.com", "timeforgoldens.com", "login.bugcutter.com", "acces-opalecenter.countmup.site", "mail-drive-oj1g.p-2f66mze8.workers.dev", "divine-sea-8f82.jernzen26.workers.dev", "www.smmrgv.vercel.app", "adobfilem.github.io", "hyqdeapmec2.webflow.io", "intermezzoconsultoria.com.br", "intermezzoconsultoria.com.br", "itsecuredesk.co.uk", "x7tq54amsloginx7tq92.portal-login-access.net", "135461223.site", "background-check-status.com", "it.one-axa.com", "www.reactiva-tucuentaa.iceiy.com", "infcuenta26.freepage.cc", "goo.su", "loginemailservices.yzz.me", "yunk-frerink.alc.onl", "signin.broker", "gsd.eon-account.com", "almaghrabifactory-com.ae-sharepoint.com", "unisusgroups.ae-sharepoint.com", "vendnue.com", "koukgruop.com", "docsviewer.online", "awesomejobfonts.top", "f005.backblazeb2.com", "microsoft-0r.github.io", "owa.goldensemolina.com.tr", "security-server-landing-page--james2606.replit.app", "cgi.s-ed1.cloud.gcore.lu", "s.teams-tb.com", "teams-lo.com", "www.the365notify.com", "security-server-landing-page--peterajiri2000.replit.app", "scsproyectos.cl", "pizzlelinchy.s3.us-east-1.amazonaws.com", "hotmail365new.s3.ap-northeast-1.amazonaws.com", "f005.backblazeb2.com", "accounts-ba666e1a.jkhjkjk.workers.dev", "wildlands.acltci.com", "validar-micuenta-outlook.yzz.me", "authentication.ms", "publicofficeoutlooknotificationscry-dpkjhfszqaa2.edgeone.dev", "security-server-page--sheryln1990.replit.app", "security-server--tabbielynn.replit.app", "security-server-page--servarog.replit.app", "microsoft0117.vercel.app", "creyt.cl", "clovdmicrsotfmailaamkagmxn2uxywe.klassik-erh.de", "microsoft-online.gr", "microsoftoffice-o365.com", "www.miccrossofteam.top", "www.connexioncompteoutlook.weebly.com", "verificarcuenta-micros0ft2026way.zya.me", "microsoft-office365.site", "microsoftsteam.live", "forms-microsoft.com", "microsofteams-setup.com", "login-microsoft-verify.online", "microsoft-account.live", "microsoft-key.online", "office365plus.net", "microsofteamsinvite.top", "hotmailli.site", "outlookinboxmessage.com", "microsofteamsinvite.live", "teams-microsofts-meet.com", "teams-microsoft-downloads.com", "outlook.surf", "onedriveshare.net", "onedrivecloud.net", "microsoft-windows-support.com", "microsoft-onedrive.org", "inbox-microsoft.com", "0nedrive.space", "salessupport-microsoft.com", "protect-outlook.com", "outlookaccessportal.com", "com-onedrive.com", "accountrecovery-outlook.com", "m365-login-microsoft.com", "microsoft-security.online", "onedrive-mysharepoint.com", "mylogin-microsoftonline.com", "ms365-onedrive.com", "accounts-login-micr0s0ft-mailsetup.com", "myaccount-microsoft365.com", "outlook.evergreenfin.ltd", "micr0s0ft0ffice365.com", "microsoftonlinesm.top", "com-microsoft-onedrive.live", "outlookk.site", "outlook-email-primecaretech.com", "microsoftfile.xyz", "microsoftpro.top", "microsoftplus.com", "microsoftolnine.com", "microsoftentraconnect.com", "microsoftteamupdate.com", "microsoftofficeph.com", "0nedrive.online", "microsoftidonline.com", "microsoftprovider.com", "microsoftfileoffline.top", "outlook.day", "microsoftonedrivesync.top", "fra-microsoft.com", "fra-microsoft.info", "fra-microsoft.store", "axisurbanmobilityllc-outlook-company.com", "outlook.beer", "outlook.baby", "urgent-microsoft.com", "teams-microsoft.cloud", "microsoftteamssviewer.com", "outlookwebupdate.com", "microsoft-messaging.com", "microsoft08619.com"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

