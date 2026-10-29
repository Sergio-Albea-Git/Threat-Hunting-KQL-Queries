# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 102
- **Retention:** rolling 30 days
- **Last updated:** 2026-10-29
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
| mfs-0519 | Microsoft 365 / Entra ID | AiTM credential proxy on free .mm.am subdomain; spoofs Entra OAuth query string with capital-I 'redirect_urI' homoglyph | 2026-10-11 | Phishunt |
| mfs-0520 | Microsoft OneDrive / Microsoft 365 | Typosquat domain stacking 'com-microsoftonline-ondrive' to make the brand read left-to-right in the hostname | 2026-10-11 | Phishunt |
| mfs-0521 | Microsoft 365 | Lookalike parent domain microsoft-ssl.com with trust-signal subdomain serving fake security-notification sign-in | 2026-10-11 | Phishunt |
| mfs-0522 | Microsoft Support / Microsoft 365 | Tech-support-themed credential page on numbered clickN.* redirector subdomains | 2026-10-11 | Phishunt |
| mfs-0523 | Microsoft Outlook / Office 365 | Typosquat host on the free yzz.me dynamic-hosting service | 2026-10-11 | Phishunt |
| mfs-0524 | Microsoft 365 | Free Vercel app-hosting abuse serving a cloned Microsoft sign-in SPA | 2026-10-11 | Phishunt |
| mfs-0525 | Microsoft Outlook | Vercel-hosted fake Outlook Web Access logon | 2026-10-11 | Phishunt |
| mfs-0526 | Microsoft OneDrive | Vercel-hosted fake OneDrive document-share gate harvesting M365 credentials | 2026-10-11 | Phishunt |
| mfs-0527 | Microsoft OneDrive | www-prefixed variant of the same Vercel OneDrive lure (separate live submission) | 2026-10-11 | OpenPhish |
| mfs-0528 | Microsoft Office 365 | AI app-builder PaaS abuse (bolt.host / Bolt.new) hosting a generated Office 365 logon clone | 2026-10-11 | OpenPhish |
| mfs-0529 | Microsoft Outlook | Compromised legitimate WordPress/CMS site hosting a static outlook.html credential-harvest page | 2026-10-11 | OpenPhish, Phishunt |
| mfs-0530 | Microsoft Word / Microsoft 365 | Free Blogspot subdomain abuse serving a Word document-view lure that pivots to a fake M365 sign-in | 2026-10-11 | Phishunt |
| mfs-0531 | Microsoft 365 | Static credential-harvest clone of the Microsoft sign-in page hosted free on GitHub Pages | 2026-10-17 | OpenPhish |
| mfs-0532 | Microsoft Outlook / Outlook Web Access | Typosquatted GitHub Pages org name ('outlook-login') serving a Spanish-language OWA credential form | 2026-10-17 | OpenPhish / Phishunt |
| mfs-0533 | Microsoft Office 365 | PhaaS kit using an /i/<32-hex> victim-ID path on an Azure-hosted lookalike subdomain (office365.* on an unrelated apex) | 2026-10-17 | Phishunt |
| mfs-0534 | Microsoft 365 | Typosquat apex m365-microsoft.com with rotating service subdomains (support/security/programme-hup/emailnotifications) | 2026-10-17 | Phishunt |
| mfs-0535 | Microsoft 365 | Same /i/<hex> PhaaS kit, French-language ('programme') lure subdomain on the m365-microsoft.com typosquat | 2026-10-17 | Phishunt |
| mfs-0536 | Microsoft 365 | Mail-notification-themed subdomain of the m365-microsoft.com typosquat, cleartext HTTP credential post | 2026-10-17 | Phishunt |
| mfs-0537 | Microsoft Office 365 | Homoglyph typosquat 'rricrosoft' (rn→m substitution) running the same /i/<hex> kit | 2026-10-17 | Phishunt |
| mfs-0538 | Microsoft account security | Security-alert lure on an email-microsoft.com typosquat; short opaque token path consistent with an AiTM relay | 2026-10-17 | Phishunt |
| mfs-0539 | Microsoft 365 / Outlook Web | AiTM reverse proxy (Tycoon2FA-style) — 'E.<base64 token>' path with a fake /microsoftonline/mailbox/upgrade query decoration to steal session cookies | 2026-10-17 | Phishunt |
| mfs-0540 | Microsoft Outlook Web Access | 'Mailbox alert' kit with /s/<campaign>/<id>/<UUID> routing path and an outlook.* subdomain on an attacker apex | 2026-10-17 | Phishunt |
| mfs-0541 | Microsoft Outlook Web Access | Domain-rotation twin of the webaccess-alert.com kit — byte-identical path, different apex, MFA/token-verification lure | 2026-10-17 | Phishunt |
| mfs-0542 | Microsoft OneDrive / SharePoint | SPA phishing kit — the ~900-char prefilled victim token sits in the URL fragment (#) so it never reaches the server log, with type=onedrive selecting the brand skin | 2026-10-17 | Phishunt |
| mfs-0543 | Microsoft Hotmail / Outlook.com | Userinfo-spoof (@) URL — 'hotmail.com-...' placed before the @ so the real host is a GoDaddy shared-hosting IP; target address prefilled via ?email= | 2026-10-17 | Phishunt |
| mfs-0544 | Microsoft 365 (login.microsoftonline.com) | Deceptive-subdomain stacking — 'login.microsoftonline-billing-verification-secured-help' is only a label on cpanel.site, billing-suspension lure | 2026-10-17 | Phishunt |
| mfs-0545 | Microsoft Live / Outlook.com | Spanish 'reactivate your account' lure on free InfinityFree (iceiy.com) hosting, cleartext HTTP | 2026-10-17 | Phishunt |
| mfs-0546 | Microsoft Outlook | Free-hosting typosquat with ?i=1 step counter, same InfinityFree operator as the reactivar-* and verificarcuenta-* sites | 2026-10-17 | Phishunt |
| mfs-0547 | Microsoft Office 365 | Zero-for-O typosquat ('0365') abusing GitBook's free docs hosting as a redirect/landing stage | 2026-10-17 | Phishunt |
| mfs-0548 | Microsoft Outlook mailbox | Weebly free-site 'mailbox validation' page with ticket-number padding in the hostname to look like a support case | 2026-10-17 | Phishunt |
| mfs-0549 | Microsoft 365 | Double-brand lure — 'microsoft' subdomain on a Citrix ShareFile-style typosquat apex, document-share pretext | 2026-10-17 | Phishunt |
| mfs-0550 | Microsoft Outlook | Fake Outlook add-in/plugin distribution domain used to prompt for mailbox credentials and OAuth consent | 2026-10-17 | Phishunt |
| mfs-0551 | Microsoft SharePoint | ccTLD typosquat impersonating a French SharePoint tenant for shared-document credential capture | 2026-10-17 | Phishunt |
| mfs-0552 | Microsoft 365 | 'Service update required' typosquat apex driving a fake M365 sign-in, fronted by Cloudflare | 2026-10-17 | Phishunt |
| mfs-0553 | Microsoft 365 Business Basic | SKU-name typosquat (licensing/renewal pretext) on IONOS hosting over cleartext HTTP | 2026-10-17 | Phishunt |
| mfs-0554 | Microsoft Office 365 | Fake licensing/support portal typosquat used as a vishing + credential-capture landing page | 2026-10-17 | Phishunt |
| mfs-0555 | Microsoft support / Microsoft 365 | Fake Cloud Solution Provider support portal on a .digital typosquat; sibling of the already-tracked click2.* subdomain | 2026-10-17 | Phishunt |
| mfs-0556 | Microsoft 365 | Country-code-flavored typosquat ('-se' Sweden) on a bulk-hosting IP shared with other Microsoft lookalikes | 2026-10-17 | Phishunt |
| mfs-0557 | Microsoft 365 | Regional typosquat ('microsoftuk') on the same bulk host as microsoft-se.us, serving a cloned MS sign-in | 2026-10-17 | Phishunt |
| mfs-0558 | Microsoft 365 | Polish-targeted typosquat on the free biz.pl second-level domain | 2026-10-17 | Phishunt |
| mfs-0559 | Microsoft 365 | Free eu.org subdomain typosquat behind Cloudflare, random two-letter suffix to evade string blocklists | 2026-10-17 | Phishunt |
| mfs-0560 | Microsoft 365 | 'microsoft' subdomain on a Chinese update-themed apex, Cloudflare-fronted, cleartext HTTP | 2026-10-17 | Phishunt |
| mfs-0561 | Microsoft Outlook mail | Brand-concatenation typosquat on a .social gTLD used as an Outlook webmail sign-in clone | 2026-10-17 | Phishunt |
| mfs-0562 | Microsoft Entra ID | Entra ID OAuth path-clone — replicates /common/oauth2/v2.0/authorize on a throwaway .sbs domain with an 'office' host label | 2026-10-19 | OpenPhish |
| mfs-0563 | Microsoft Live / Microsoft Account | Full HTML clone of login.live.com (reuses genuine jsDisabled.srf endpoint and uaid/mkt/lc params) on attacker domain oauth-live.com | 2026-10-19 | OpenPhish |
| mfs-0564 | Microsoft Live / Microsoft Account | Typosquat/brand-combo domain (oauth-live.com) serving a 'login.' host that fronts the Microsoft Account sign-in clone | 2026-10-18 | OpenPhish |
| mfs-0565 | Microsoft Teams / Microsoft 365 | Newly-registered (5-day-old) domain replicating the Teams sign-in screen and post-login Teams UI to harvest M365 credentials | 2026-10-18 | CyberSecurityNews (researcher Steven Lim) |
| mfs-0566 | Microsoft Teams / Microsoft 365 | Victim-targeted subdomain of the teams-cloud.live Teams clone — org name prefixed as a subdomain for tailored lures (healthcare/pharma targeting) | 2026-10-18 | CyberSecurityNews (researcher Steven Lim) |
| mfs-0567 | Microsoft Outlook Web App (Exchange/OWA) | Compromised legitimate website hosting an OWA sign-in kit under a /EN/owa/ directory | 2026-10-19 | OpenPhish |
| mfs-0568 | Microsoft Outlook / Microsoft 365 | Compromised WordPress site — static outlook.html credential-harvest page dropped under /wp-content/uploads/ with randomized nested directories | 2026-10-18 | OpenPhish / Phishunt |
| mfs-0569 | Microsoft Office 365 | HTML credential-harvest page hosted in a public Backblaze B2 bucket (trusted-cloud hosting abuse); same 'myoffice.html' kit family as prior B2 buckets | 2026-10-18 | OpenPhish |
| mfs-0570 | Microsoft 365 / SharePoint-OneDrive | Cloudflare Workers-hosted 'shared document' lure chaining to an M365 sign-in prompt; hostname embeds victim-org and 'mcs365' strings | 2026-10-18 | OpenPhish |
| mfs-0571 | Microsoft 365 | AiTM phishing-as-a-service portal replicating the Microsoft 'Pick an account' selection screen, victim keyed by GUID in the ?c= parameter | 2026-10-17 | OpenPhish |
| mfs-0572 | Microsoft 365 | AiTM kit second-stage account-selection URL on the same safe365apps.com infrastructure (shorter ?c= victim token) | 2026-10-17 | OpenPhish |
| mfs-0573 | Microsoft 365 | Typosquat domain m365-microsoft.com with per-victim '/i/<32-hex>' tracking links; 'security.' subdomain used for account-security-alert lures | 2026-10-19 | Phishunt |
| mfs-0574 | Microsoft Outlook / Office 365 | Free Korean shared-hosting (dothome.co.kr) subdomain typosquat ('outlook365livee') serving an Outlook webmail sign-in clone | 2026-10-19 | Phishunt |
| mfs-0575 | Microsoft 365 / Entra ID | Typosquat domain mimicking the login.microsoftonline.com/common/oauth2 OpenID sign-in path, hosted on a cPanel default 'cpanel.site' hostname | 2026-10-23 | Phishunt |
| mfs-0576 | Microsoft 365 / Outlook Web | Mail-themed subdomain of the same microsoftonline-com-common-signin-openid typosquat kit on shared cPanel infrastructure | 2026-10-23 | Phishunt |
| mfs-0577 | Microsoft 365 | Billing/licence-expiry lure on a long deceptive-label typosquat where 'login.microsoftonline' is placed in the subdomain, not the registrable domain | 2026-10-23 | Phishunt |
| mfs-0578 | Microsoft 365 | Per-victim random 8-char subdomain prepended to the microsoftonline-billing-verification typosquat (wildcard DNS) for link-uniqueness and sandbox evasion | 2026-10-23 | Phishunt |
| mfs-0579 | Microsoft 365 | Operator test artifact of the same wildcard kit — 'test.' label stacked on the per-victim subdomain, confirming active kit development | 2026-10-23 | Phishunt |
| mfs-0580 | Microsoft 365 | Second per-victim wildcard subdomain of the billing-verification typosquat kit on the same 161.35.102.243 host | 2026-10-23 | Phishunt |
| mfs-0581 | Microsoft 365 | Same kit on a second DigitalOcean node (104.248.114.136) with a 'www.' + random-label wildcard FQDN | 2026-10-23 | Phishunt |
| mfs-0582 | Microsoft 365 | Microsoft billing-verification credential harvester, wildcard subdomain variant on 104.248.114.136 | 2026-10-23 | Phishunt |
| mfs-0583 | Microsoft 365 | Wildcard-DNS Microsoft 365 billing lure on shared cPanel hosting | 2026-10-23 | Phishunt |
| mfs-0584 | Microsoft 365 / Azure | Brand-keyword typosquat domain ('microsoft' + 'cloud verification') serving an account-verification credential prompt over plain HTTP | 2026-10-23 | Phishunt |
| mfs-0585 | Microsoft OneDrive / Entra ID SSO | 'sso.' subdomain on a hyphenated microsoft-onedrive typosquat to imitate a federated single-sign-on endpoint for a OneDrive share lure | 2026-10-23 | Phishunt |
| mfs-0586 | Microsoft Outlook | ccTLD typosquat of Outlook webmail (.de) hosting a mailbox sign-in harvester | 2026-10-23 | Phishunt |
| mfs-0587 | Microsoft Outlook | 'mail.' subdomain of the outlookmails.de typosquat, presenting a fake Outlook mailbox login | 2026-10-23 | Phishunt |
| mfs-0588 | Microsoft Outlook | Free-hosting abuse — auto-generated Vercel subdomain (adjective-numeral naming) serving a cloned Outlook sign-in page | 2026-10-23 | Phishunt |
| mfs-0589 | Microsoft Outlook | Second Vercel-hosted Outlook sign-in clone from the same operator naming scheme ('outlook-<word>') | 2026-10-23 | Phishunt |
| mfs-0590 | Microsoft 365 | Apex of the m365-microsoft[.]com typosquat used by an ongoing campaign that also rotates support./security./emailnotifications. subdomains with /i/<32-hex> per-victim tokens | 2026-10-23 | Phishunt |
| mfs-0591 | Microsoft 365 | Regional-branding typosquat ('Microsoft Africa') on .org, a TLD Microsoft does not use for tenant sign-in | 2026-10-23 | Phishunt |
| mfs-0592 | Microsoft Office 365 | Compromised legitimate WordPress site hosting an Office 365 PHP phishing kit in an attacker-created directory ('linkmyGod/office-3D8') | 2026-10-23 | OpenPhish |
| mfs-0593 | Microsoft Outlook | Credential-harvesting HTML page hosted on abused Backblaze B2 public bucket (legit-cloud hosting for TLS/reputation) | 2026-10-25 | OpenPhish (via phishunt.io) |
| mfs-0594 | Microsoft 365 | Typosquat/brand-abuse landing page on free Vercel hosting; incrementing suffix indicates serial redeployment | 2026-10-25 | OpenPhish (via phishunt.io) |
| mfs-0595 | Microsoft Outlook | Fake Outlook sign-in page on Vercel free tier; Vercel auto-generated three-word subdomain pattern | 2026-10-24 | OpenPhish (via phishunt.io) |
| mfs-0596 | Microsoft Outlook | Brand-stacked typosquat (multiple Microsoft brand tokens in one label) on Vercel | 2026-10-24 | OpenPhish (via phishunt.io) |
| mfs-0597 | Microsoft 365 | Fake M365 login page (DigitalOcean-hosted) reached via hidden link in a PDF delivered through legitimate Frame.io share notifications, with a Cloudflare Pages hop — campaign 'Phantom Preview' | 2026-10-20 | Ocean Security (via Hackread) |
| mfs-0598 | Microsoft Teams | Typosquat domain cloning the full Microsoft Teams sign-in interface; flagged four days after registration | 2026-10-08 | Steven Lim (@0x534c) via CyberSecurityNews |
| mfs-0599 | Microsoft 365 | Wazza phishing kit — OAuth device-code phishing landing page on Cloudflare Workers; leetspeak Microsoft/Azure service tokens in a long hyphenated subdomain | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0600 | Microsoft 365 | Wazza kit device-code phishing landing page on Cloudflare Workers (SSO-themed leetspeak subdomain) | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0601 | Microsoft 365 / Office | Wazza kit device-code phishing landing page on Cloudflare Workers; also used as a parent for randomized victim-specific subdomains | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0602 | Microsoft 365 / Teams / Intune | Wazza kit device-code phishing landing page on Cloudflare Workers (Teams/Intune-themed leetspeak subdomain) | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0603 | Microsoft OneDrive / Microsoft 365 | Wazza kit per-victim randomized subdomain over a OneDrive/Entra-themed Cloudflare Workers parent; device-code flow | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0604 | Microsoft 365 / Azure | Wazza kit per-victim randomized subdomain over an Azure-service-themed Workers parent; device-code credential/token theft | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0605 | Microsoft 365 / Office | Wazza kit per-victim randomized subdomain over the Windows/Office-themed Workers parent; device-code phishing | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0606 | Microsoft 365 | Wazza kit preloader/redirector on a compromised .eu site (random 17-char subdomain + short path) that hands off to the M365 device-code landing page | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0607 | Microsoft 365 / OneDrive | Google Sites staging page used as the first hop in the Wazza chain (abuses google.com reputation) before redirecting to the M365 device-code landing page | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0608 | Microsoft 365 | Google Sites 'secure PDF' lure page in the Wazza chain; PDF-document theme leading to a fake M365 authentication step | 2026-10-20 | LevelBlue SpiderLabs |
| mfs-0609 | Microsoft OneDrive | Compromised legitimate .cl site hosting a static HTML 'Access your file - OneDrive' document lure that pivots to a credential form | 2026-10-29 | phishunt.io (confirmed live, page title 'Access your file - OneDrive') |
| mfs-0610 | Microsoft SharePoint Online | Brand-concatenation typosquat domain with a per-victim 'normal' tracking token in the query string | 2026-10-29 | OpenPhish community feed |
| mfs-0611 | Microsoft | Homoglyph typosquat (microsofl ← microsoft) run as a subdomain on a multi-brand phishing-as-a-service host that also serves bank lures | 2026-10-29 | OpenPhish community feed |
| mfs-0612 | Microsoft Outlook | Free website-builder (Flazio) subdomain hosting an Outlook sign-in clone — abuses a trusted SaaS parent domain and valid wildcard TLS | 2026-10-29 | OpenPhish community feed |
| mfs-0613 | Microsoft 365 | Vercel-hosted static sign-in clone using a numeric-suffix throwaway project name for rapid redeployment | 2026-10-29 | phishunt.io |
| mfs-0614 | Microsoft OneDrive | Vercel-hosted OneDrive document-share lure; same naming family as the previously tracked onedrive-4-nine.vercel.app | 2026-10-29 | phishunt.io |
| mfs-0615 | Microsoft OneDrive | Lookalike apex domain (sa-onedrive.com) with per-target subdomain, suggesting Saudi/regional org-specific credential harvesting | 2026-10-29 | phishunt.io |
| mfs-0616 | Microsoft Outlook | Spanish-language 'validate my account' Outlook lure on free yzz.me dynamic-DNS hosting; sibling of the tracked login-outlook365.yzz.me | 2026-10-29 | phishunt.io |
| mfs-0617 | Microsoft 365 / Entra ID | ccTLD typosquat imitating login.microsoftonline.com via a hyphenated .gr registration | 2026-10-29 | phishunt.io |
| mfs-0618 | Microsoft | IT-support/telemetry-themed lookalike domain used as a pretext landing page before credential capture | 2026-10-29 | phishunt.io |
| mfs-0619 | Microsoft Outlook | Free-subdomain-provider squat — 'outlook' registered as a label under the us.org shared zone to look like an official Outlook host | 2026-10-29 | phishunt.io |
| mfs-0620 | Microsoft 365 / Entra ID | Cloudflare Workers relay for the 'Wazza' OAuth device-code phishing kit — victim enters the attacker's code at microsoft.com/devicelogin, tokens are exfiltrated through this worker | 2026-10-21 | Security Arsenal / AlienVault OTX pulse analysis (Wazza device code phishing kit) |

### mfs-0519 — Microsoft 365 / Entra ID

```text
https://onmicrosoftonline-mmscrmcustomers.mm.am/login?method=signin&mode=secure&client_id=4765445b-32c6-49b0-83e6-1d93765276ca&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Flogin.microsoftonline.com%2F
```

- **Domain:** `onmicrosoftonline-mmscrmcustomers.mm.am`
- **Technique:** AiTM credential proxy on free .mm.am subdomain; spoofs Entra OAuth query string with capital-I 'redirect_urI' homoglyph
- **Detection:** Hunt proxy/DNS for the literal parameter 'redirect_urI=' (capital i) and for client_id 4765445b-32c6-49b0-83e6-1d93765276ca on any host that is not login.microsoftonline.com — same kit as the earlier acltci.com node
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0520 — Microsoft OneDrive / Microsoft 365

```text
https://site.com-microsoftonline-ondrive.ca
```

- **Domain:** `site.com-microsoftonline-ondrive.ca`
- **Technique:** Typosquat domain stacking 'com-microsoftonline-ondrive' to make the brand read left-to-right in the hostname
- **Detection:** Alert on newly registered domains containing 'microsoftonline' as a label substring rather than as the registrable domain; also flag the 'ondrive' misspelling
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0521 — Microsoft 365

```text
https://notifications.microsoft-ssl.com
```

- **Domain:** `notifications.microsoft-ssl.com`
- **Technique:** Lookalike parent domain microsoft-ssl.com with trust-signal subdomain serving fake security-notification sign-in
- **Detection:** Block the whole microsoft-ssl.com zone and hunt NRD registrations combining 'microsoft' with security words (ssl, secure, cert, verify) as hyphenated parent domains
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0522 — Microsoft Support / Microsoft 365

```text
https://click2.microsoftsupportcenter.digital
```

- **Domain:** `click2.microsoftsupportcenter.digital`
- **Technique:** Tech-support-themed credential page on numbered clickN.* redirector subdomains
- **Detection:** Wildcard-block *.microsoftsupportcenter.digital — enumerated click1..clickN subdomains rotate; this extends the known click5/click6 nodes
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0523 — Microsoft Outlook / Office 365

```text
http://login-outlook365.yzz.me
```

- **Domain:** `login-outlook365.yzz.me`
- **Technique:** Typosquat host on the free yzz.me dynamic-hosting service
- **Detection:** Treat *.yzz.me as high-risk for Microsoft-themed phishing (third observed node after validar-micuenta-outlook and loginemailservices); block the TLD-level provider for corporate egress
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0524 — Microsoft 365

```text
http://microsoft-alpha.vercel.app
```

- **Domain:** `microsoft-alpha.vercel.app`
- **Technique:** Free Vercel app-hosting abuse serving a cloned Microsoft sign-in SPA
- **Detection:** Flag *.vercel.app hostnames whose project slug contains microsoft/outlook/onedrive/office; legitimate Microsoft never serves auth from vercel.app
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0525 — Microsoft Outlook

```text
http://outlook-serv-coral.vercel.app
```

- **Domain:** `outlook-serv-coral.vercel.app`
- **Technique:** Vercel-hosted fake Outlook Web Access logon
- **Detection:** Same Vercel slug heuristic; 'serv'/'srv' + brand token is a recurring naming pattern in this cluster
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0526 — Microsoft OneDrive

```text
https://onedrive-4-nine.vercel.app
```

- **Domain:** `onedrive-4-nine.vercel.app`
- **Technique:** Vercel-hosted fake OneDrive document-share gate harvesting M365 credentials
- **Detection:** Match Vercel projects with brand + numeric-word padding (4-nine, 2-five); pair with Referer analysis from mail gateways
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0527 — Microsoft OneDrive

```text
http://www.onedrive-4-nine.vercel.app/
```

- **Domain:** `www.onedrive-4-nine.vercel.app`
- **Technique:** www-prefixed variant of the same Vercel OneDrive lure (separate live submission)
- **Detection:** Block the apex and www variant together — Vercel resolves both; wildcard the project slug, not the single FQDN
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0528 — Microsoft Office 365

```text
https://network-office-cm51.bolt.host/
```

- **Domain:** `network-office-cm51.bolt.host`
- **Technique:** AI app-builder PaaS abuse (bolt.host / Bolt.new) hosting a generated Office 365 logon clone
- **Detection:** Add bolt.host to the PaaS watchlist alongside replit.app/vercel.app/workers.dev; alert on *.bolt.host containing office/microsoft/outlook plus a random alphanumeric suffix
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0529 — Microsoft Outlook

```text
https://namastespa.ca/everybin/outlook.html
```

- **Domain:** `namastespa.ca`
- **Technique:** Compromised legitimate WordPress/CMS site hosting a static outlook.html credential-harvest page
- **Detection:** Hunt web-proxy logs for static filenames outlook.html / office365.html / onedrive-verify*.html on unrelated business domains — same TTP as the intermezzoconsultoria.com.br and creyt.cl nodes
- **Source:** OpenPhish, Phishunt — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0530 — Microsoft Word / Microsoft 365

```text
https://microsoftwordob.blogspot.com
```

- **Domain:** `microsoftwordob.blogspot.com`
- **Technique:** Free Blogspot subdomain abuse serving a Word document-view lure that pivots to a fake M365 sign-in
- **Detection:** Alert on *.blogspot.com hostnames containing microsoft/outlook/office — recurring free-platform cluster with jimdofree.com and weebly.com nodes
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-11

### mfs-0531 — Microsoft 365

```text
https://n2cknem.github.io/microsoft/
```

- **Domain:** `n2cknem.github.io`
- **Technique:** Static credential-harvest clone of the Microsoft sign-in page hosted free on GitHub Pages
- **Detection:** Alert on outbound HTTP to *.github.io paths containing /microsoft, /office, /owa — no legitimate Entra ID auth ever lands on github.io
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0532 — Microsoft Outlook / Outlook Web Access

```text
https://outlook-login.github.io/Validar
```

- **Domain:** `outlook-login.github.io`
- **Technique:** Typosquatted GitHub Pages org name ('outlook-login') serving a Spanish-language OWA credential form
- **Detection:** Hunt proxy logs for github.io subdomains whose label contains outlook/login/signin; also flag GitHub Pages referers preceding POSTs to non-Microsoft hosts
- **Source:** OpenPhish / Phishunt — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0533 — Microsoft Office 365

```text
https://office365.internal-alerts.com/i/d5b9af0d256f14c03ab8396a78d3687bf
```

- **Domain:** `office365.internal-alerts.com`
- **Technique:** PhaaS kit using an /i/<32-hex> victim-ID path on an Azure-hosted lookalike subdomain (office365.* on an unrelated apex)
- **Detection:** Regex URL path ^/i/[0-9a-f]{32,33}$ on non-Microsoft hosts resolving to 20.50.64.14 — one shared kit across several of today's domains
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0534 — Microsoft 365

```text
http://support.m365-microsoft.com/i/ab041e84e499243eca3e98fb328201632
```

- **Domain:** `support.m365-microsoft.com`
- **Technique:** Typosquat apex m365-microsoft.com with rotating service subdomains (support/security/programme-hup/emailnotifications)
- **Detection:** Block the whole m365-microsoft.com apex plus any new subdomain under it; the apex is not Microsoft-owned and all labels resolve to 20.50.64.14
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0535 — Microsoft 365

```text
https://programme-hup.m365-microsoft.com/i/d721e212eb3094bfd99c9d047a94edaeb
```

- **Domain:** `programme-hup.m365-microsoft.com`
- **Technique:** Same /i/<hex> PhaaS kit, French-language ('programme') lure subdomain on the m365-microsoft.com typosquat
- **Detection:** Wildcard-block *.m365-microsoft.com; alert on first-seen subdomains of a domain already flagged for credential phishing
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0536 — Microsoft 365

```text
http://emailnotifications.m365-microsoft.com/i/a3ce2879ab8b04bd4a96eaabe3f1dae68
```

- **Domain:** `emailnotifications.m365-microsoft.com`
- **Technique:** Mail-notification-themed subdomain of the m365-microsoft.com typosquat, cleartext HTTP credential post
- **Detection:** Flag any plaintext HTTP request to a host containing 'microsoft' — Microsoft enforces HSTS, so HTTP to an MS-branded host is phishing by definition
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0537 — Microsoft Office 365

```text
https://office365.rricrosoft-offices.org/i/df3667320560f4a8a9918ef9f3f4c4383
```

- **Domain:** `office365.rricrosoft-offices.org`
- **Technique:** Homoglyph typosquat 'rricrosoft' (rn→m substitution) running the same /i/<hex> kit
- **Detection:** Fuzzy-match registered domains against 'microsoft' with rn/m, vv/w, l/I substitutions; same 20.50.64.14 infrastructure cluster
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0538 — Microsoft account security

```text
https://security.email-microsoft.com/diyc_smavt1av3ltaq
```

- **Domain:** `security.email-microsoft.com`
- **Technique:** Security-alert lure on an email-microsoft.com typosquat; short opaque token path consistent with an AiTM relay
- **Detection:** Host resolves into 212.104.128.0/24 — the same /24 as the auth.properties AiTM cluster; block that netblock and alert on any MS-branded hostname in it
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0539 — Microsoft 365 / Outlook Web

```text
https://auth.properties/E.K7TNFIWMOeb1jA?/microsoftonline/mailbox/upgrade
```

- **Domain:** `auth.properties`
- **Technique:** AiTM reverse proxy (Tycoon2FA-style) — 'E.<base64 token>' path with a fake /microsoftonline/mailbox/upgrade query decoration to steal session cookies
- **Detection:** Regex ^/E\.[A-Za-z0-9_-]{10,}$ on any non-Microsoft host; this family rotates across authentication.ms, multi-factor.link, signin.broker, auth.properties — block the pattern, not the domain
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0540 — Microsoft Outlook Web Access

```text
https://outlook.webaccess-alert.com/s/63bzgfsvbwsfcdx7y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a
```

- **Domain:** `outlook.webaccess-alert.com`
- **Technique:** 'Mailbox alert' kit with /s/<campaign>/<id>/<UUID> routing path and an outlook.* subdomain on an attacker apex
- **Detection:** Hunt the literal campaign ID 63bzgfsvbwsfcdx7y9 and the path shape /s/<alnum18>/<hex6>/<uuid> — identical URI is live on at least two rotating domains
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0541 — Microsoft Outlook Web Access

```text
https://outlook.verifytoken.com/s/63bzgfsvbwsfcdx7y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a
```

- **Domain:** `outlook.verifytoken.com`
- **Technique:** Domain-rotation twin of the webaccess-alert.com kit — byte-identical path, different apex, MFA/token-verification lure
- **Detection:** Pivot on the shared URI to discover sibling domains; alert on any new apex with an 'outlook' subdomain serving path prefix /s/63bzgfsvbwsfcdx7y9/
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0542 — Microsoft OneDrive / SharePoint

```text
https://onedrive.at-us.therelayservice.com/matpwp#/main?type=onedrive&locale=en&token=klb1x-bsfowhfwldwy5w5kex8sqynzrdesvfmnxmjl0tdf7uku8us441ssdv8qxwab7r07sx8d2tcaaxbilw7jrzwi1bt5g3m5qzpqncstyknfwj-yqfe_r7n9a3fu-ucws29093snwgphbneuqsxk8mdo1puqplqq_lyyy-z2vqt0erqcmg8tcawlfl4sskggccbqduptoyfosujteijqvlgjpzlcwk0wzrnqxxdxcdnwju5qyv2u4bj3idzgs8v6qa5yn4seek0heypiiacbhbz-jsqmkneijig233aier9rnsfanl5bt7eowf4952rktiz7odbtltsmxsfazcm3ga1xvespeobe4utzckdaigmdsculmol47bkalfeo3zqnkpb9hw-0acrojr0rpyclysnuwlrdsj3cwj5fljekfatvnxgqf6t6guofe50es9j4ljrt51cmwecxfrx7gnrdtg4vqsf_loqemh0n9qs_6pgwf78nhmzq2uzw-h3syvcvq9ymx-socacp8xhredrbz2z64w4xkxwty3fqjcnrfittqfgpdtnzmyg77ykywog3xcnqzclem2_oylu4f8ynj210a8hcdlwhk_kfpo-l-rvhhjwr8rvlblvvkztoo5nswd6zvqyiyh6c14wlbgmps9-4hbixryj-niycq2ngj7cha9mbmdeuln-4mx3i54
```

- **Domain:** `onedrive.at-us.therelayservice.com`
- **Technique:** SPA phishing kit — the ~900-char prefilled victim token sits in the URL fragment (#) so it never reaches the server log, with type=onedrive selecting the brand skin
- **Detection:** Alert on URLs >500 chars containing '#/main?type=' with a token= fragment; fragment-carried state defeats proxy URL logging, so inspect full-URI browser telemetry
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0543 — Microsoft Hotmail / Outlook.com

```text
https://hotmail.com-desenrolabrasil638946990@81.190.202.64.host.secureserver.net/desenrola/?email=sinhorinho@outlook.com
```

- **Domain:** `81.190.202.64.host.secureserver.net`
- **Technique:** Userinfo-spoof (@) URL — 'hotmail.com-...' placed before the @ so the real host is a GoDaddy shared-hosting IP; target address prefilled via ?email=
- **Detection:** Flag any URL containing '@' in the authority where the userinfo includes a known brand string; also alert on ?email= prefill parameters to non-corporate hosts
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0544 — Microsoft 365 (login.microsoftonline.com)

```text
https://www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site
```

- **Domain:** `www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site`
- **Technique:** Deceptive-subdomain stacking — 'login.microsoftonline-billing-verification-secured-help' is only a label on cpanel.site, billing-suspension lure
- **Detection:** Alert when 'login.microsoftonline' appears as a subdomain label rather than as the registrable domain; eTLD+1 of cpanel.site is never Microsoft
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0545 — Microsoft Live / Outlook.com

```text
http://reactivar-microsoft-live.iceiy.com
```

- **Domain:** `reactivar-microsoft-live.iceiy.com`
- **Technique:** Spanish 'reactivate your account' lure on free InfinityFree (iceiy.com) hosting, cleartext HTTP
- **Detection:** Block *.iceiy.com / *.yzz.me / *.zya.me / *.hstn.me — the InfinityFree free-hosting family is heavily reused by this Spanish-language Microsoft campaign
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0546 — Microsoft Outlook

```text
https://outlook-email-2026.hstn.me/?i=1
```

- **Domain:** `outlook-email-2026.hstn.me`
- **Technique:** Free-hosting typosquat with ?i=1 step counter, same InfinityFree operator as the reactivar-* and verificarcuenta-* sites
- **Detection:** Hunt hostnames matching (outlook|micros0ft|hotmail).*-?20(25|26) on free-hosting eTLDs; ?i=1 marks step 1 of this kit's flow
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0547 — Microsoft Office 365

```text
https://0365-microsoft.gitbook.io
```

- **Domain:** `0365-microsoft.gitbook.io`
- **Technique:** Zero-for-O typosquat ('0365') abusing GitBook's free docs hosting as a redirect/landing stage
- **Detection:** Alert on digit-for-letter swaps (0365, micr0s0ft, 0nedrive) and on *.gitbook.io / *.gitbook.com hosts referenced in mail — SaaS doc platforms are current staging favorites
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0548 — Microsoft Outlook mailbox

```text
http://401283-outlookmailbox-00012-validate.weebly.com
```

- **Domain:** `401283-outlookmailbox-00012-validate.weebly.com`
- **Technique:** Weebly free-site 'mailbox validation' page with ticket-number padding in the hostname to look like a support case
- **Detection:** Regex ^[0-9]{5,7}-.*(outlook|mailbox|office|validate).*\.weebly\.com$; Weebly/Webflow/Typedream subdomains carry no legitimate Microsoft auth
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0549 — Microsoft 365

```text
https://microsoft.citrix-sharing.com
```

- **Domain:** `microsoft.citrix-sharing.com`
- **Technique:** Double-brand lure — 'microsoft' subdomain on a Citrix ShareFile-style typosquat apex, document-share pretext
- **Detection:** Alert on hostnames stacking two vendor brands (microsoft.<othervendor>-*.com); legitimate Citrix domains never host a microsoft.* label
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0550 — Microsoft Outlook

```text
https://plugins.sugar-outlook.com
```

- **Domain:** `plugins.sugar-outlook.com`
- **Technique:** Fake Outlook add-in/plugin distribution domain used to prompt for mailbox credentials and OAuth consent
- **Detection:** Watch for Entra ID consent grants to non-verified publishers plus DNS to hostnames pairing 'outlook' with 'plugin/addin/connector'
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0551 — Microsoft SharePoint

```text
https://microsoft-sharepoint.fr
```

- **Domain:** `microsoft-sharepoint.fr`
- **Technique:** ccTLD typosquat impersonating a French SharePoint tenant for shared-document credential capture
- **Detection:** Alert on hyphenated brand pairs on ccTLDs (microsoft-sharepoint.*, onedrive-microsoft.*); real tenants always sit under sharepoint.com
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0552 — Microsoft 365

```text
https://microsoft365updates.com
```

- **Domain:** `microsoft365updates.com`
- **Technique:** 'Service update required' typosquat apex driving a fake M365 sign-in, fronted by Cloudflare
- **Detection:** Block newly registered domains combining microsoft/m365/office with update(s)/alert(s)/notice; check RDAP creation date <30 days
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0553 — Microsoft 365 Business Basic

```text
http://microsoft365businessbasic.com
```

- **Domain:** `microsoft365businessbasic.com`
- **Technique:** SKU-name typosquat (licensing/renewal pretext) on IONOS hosting over cleartext HTTP
- **Detection:** Hunt domains built from Microsoft SKU names (businessbasic, e3, e5, businesspremium); HTTP-only MS-branded hosts are high-confidence phishing
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0554 — Microsoft Office 365

```text
http://office365licensingsupport.com
```

- **Domain:** `office365licensingsupport.com`
- **Technique:** Fake licensing/support portal typosquat used as a vishing + credential-capture landing page
- **Detection:** Flag domains concatenating office365/m365 with support|licensing|billing|renewal; correlate with inbound 'license expired' mail subjects
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0555 — Microsoft support / Microsoft 365

```text
https://csp.microsoftsupportcenter.digital
```

- **Domain:** `csp.microsoftsupportcenter.digital`
- **Technique:** Fake Cloud Solution Provider support portal on a .digital typosquat; sibling of the already-tracked click2.* subdomain
- **Detection:** Wildcard-block *.microsoftsupportcenter.digital — the apex is attacker-controlled and spins new subdomains (click2, csp, …) per wave
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0556 — Microsoft 365

```text
https://microsoft-se.us
```

- **Domain:** `microsoft-se.us`
- **Technique:** Country-code-flavored typosquat ('-se' Sweden) on a bulk-hosting IP shared with other Microsoft lookalikes
- **Detection:** Shares 64.191.166.0/24 with microsoftuk.co — enumerate that netblock's reverse DNS for additional microsoft<cc> squats
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0557 — Microsoft 365

```text
https://microsoftuk.co
```

- **Domain:** `microsoftuk.co`
- **Technique:** Regional typosquat ('microsoftuk') on the same bulk host as microsoft-se.us, serving a cloned MS sign-in
- **Detection:** Pattern-match microsoft<2-letter-cc> and microsoft-<cc> registrations; block the 64.191.166.0/24 cluster
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0558 — Microsoft 365

```text
https://microsoftpl.biz.pl
```

- **Domain:** `microsoftpl.biz.pl`
- **Technique:** Polish-targeted typosquat on the free biz.pl second-level domain
- **Detection:** Treat *.biz.pl / *.waw.pl and similar free Polish SLDs as untrusted for any brand-bearing label; alert on 'microsoft' + locale suffix
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0559 — Microsoft 365

```text
https://microsoftjk.eu.org
```

- **Domain:** `microsoftjk.eu.org`
- **Technique:** Free eu.org subdomain typosquat behind Cloudflare, random two-letter suffix to evade string blocklists
- **Detection:** Block *.eu.org for brand-bearing labels; alert on 'microsoft' + 1-3 random chars, a generator signature across this operator's domains
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0560 — Microsoft 365

```text
http://microsoft.updata.net.cn
```

- **Domain:** `microsoft.updata.net.cn`
- **Technique:** 'microsoft' subdomain on a Chinese update-themed apex, Cloudflare-fronted, cleartext HTTP
- **Detection:** Alert on a 'microsoft' label as a subdomain of any non-Microsoft eTLD+1 — a simple, very high-signal rule for sign-in phishing
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0561 — Microsoft Outlook mail

```text
http://outlookmail.social
```

- **Domain:** `outlookmail.social`
- **Technique:** Brand-concatenation typosquat on a .social gTLD used as an Outlook webmail sign-in clone
- **Detection:** Monitor new gTLD registrations (.social, .surf, .day, .beer) containing outlook/hotmail/onedrive — this actor favors cheap novelty TLDs
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0562 — Microsoft Entra ID

```text
http://office.rox-klimatechnik.sbs/common/oauth2/v2.0/authorize/
```

- **Domain:** `office.rox-klimatechnik.sbs`
- **Technique:** Entra ID OAuth path-clone — replicates /common/oauth2/v2.0/authorize on a throwaway .sbs domain with an 'office' host label
- **Detection:** Alert on outbound HTTP to any non-microsoft TLD whose URI path contains '/common/oauth2/v2.0/authorize' — the path is unique to Microsoft identity endpoints and never legitimate off *.microsoftonline.com/*.microsoft.com
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-19

### mfs-0563 — Microsoft Live / Microsoft Account

```text
https://mslogin.oauth-live.com/jsDisabled.srf?mkt=EN-US&lc=1033&uaid=84651455702342cebdc1e14c631cf2ee
```

- **Domain:** `mslogin.oauth-live.com`
- **Technique:** Full HTML clone of login.live.com (reuses genuine jsDisabled.srf endpoint and uaid/mkt/lc params) on attacker domain oauth-live.com
- **Detection:** Hunt proxy/DNS for requests to '*.srf' URIs (ppsecure, jsDisabled.srf, GetCredentialType) on hosts outside login.live.com/login.microsoftonline.com; also pivot on any domain combining 'oauth' + 'live'
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-19

### mfs-0564 — Microsoft Live / Microsoft Account

```text
http://login.oauth-live.com/
```

- **Domain:** `login.oauth-live.com`
- **Technique:** Typosquat/brand-combo domain (oauth-live.com) serving a 'login.' host that fronts the Microsoft Account sign-in clone
- **Detection:** Block the apex oauth-live.com and alert on newly-observed domains matching regex (oauth|login|sso).*-?(live|msonline|microsoft) registered <30 days
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-18

### mfs-0565 — Microsoft Teams / Microsoft 365

```text
https://teams-cloud.live/
```

- **Domain:** `teams-cloud.live`
- **Technique:** Newly-registered (5-day-old) domain replicating the Teams sign-in screen and post-login Teams UI to harvest M365 credentials
- **Detection:** Flag first-seen traffic to domains containing 'teams' on the .live/.cloud TLDs; correlate with brand-new WHOIS creation dates (<14 days) in your NRD feed
- **Source:** CyberSecurityNews (researcher Steven Lim) — https://cybersecuritynews.com/teams-domain-login-page/
- **Status:** active
- **First seen:** 2026-10-18

### mfs-0566 — Microsoft Teams / Microsoft 365

```text
https://amgen.teams-cloud.live/
```

- **Domain:** `amgen.teams-cloud.live`
- **Technique:** Victim-targeted subdomain of the teams-cloud.live Teams clone — org name prefixed as a subdomain for tailored lures (healthcare/pharma targeting)
- **Detection:** Search DNS/SNI logs for your own company name appearing as the left-most label of an external domain (e.g. '<yourorg>.*'); that pattern is a reliable tailored-phish signal
- **Source:** CyberSecurityNews (researcher Steven Lim) — https://cybersecuritynews.com/teams-domain-login-page/
- **Status:** active
- **First seen:** 2026-10-18

### mfs-0567 — Microsoft Outlook Web App (Exchange/OWA)

```text
https://abcgil.com/EN/owa/
```

- **Domain:** `abcgil.com`
- **Technique:** Compromised legitimate website hosting an OWA sign-in kit under a /EN/owa/ directory
- **Detection:** Alert on '/owa/' or '/exchange/' URI paths requested on external hosts that are not your own Exchange/Outlook namespaces
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-19

### mfs-0568 — Microsoft Outlook / Microsoft 365

```text
http://dayoadeyemo.com/wp-content/uploads/e1tyxmv/dwlqv1x/ubmqvdy/new/outlook.html
```

- **Domain:** `dayoadeyemo.com`
- **Technique:** Compromised WordPress site — static outlook.html credential-harvest page dropped under /wp-content/uploads/ with randomized nested directories
- **Detection:** Hunt web-proxy logs for '/wp-content/uploads/' paths ending in .html with Microsoft-brand filenames (outlook.html, myoffice.html, office365.html); uploads dirs should serve media, never HTML login forms
- **Source:** OpenPhish / Phishunt — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-18

### mfs-0569 — Microsoft Office 365

```text
https://f005.backblazeb2.com/file/sinere/myoffice.html
```

- **Domain:** `f005.backblazeb2.com`
- **Technique:** HTML credential-harvest page hosted in a public Backblaze B2 bucket (trusted-cloud hosting abuse); same 'myoffice.html' kit family as prior B2 buckets
- **Detection:** Block/alert on *.backblazeb2.com '/file/*/*.html' object fetches from user endpoints — B2 buckets serving HTML to browsers is near-universally phishing in enterprise traffic
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-18

### mfs-0570 — Microsoft 365 / SharePoint-OneDrive

```text
https://spazioaperto-shared-document.live-document-mcs365980.workers.dev/
```

- **Domain:** `spazioaperto-shared-document.live-document-mcs365980.workers.dev`
- **Technique:** Cloudflare Workers-hosted 'shared document' lure chaining to an M365 sign-in prompt; hostname embeds victim-org and 'mcs365' strings
- **Detection:** Alert on *.workers.dev hostnames containing document/share/drive/365/mcs tokens; most orgs can safely treat user-facing workers.dev as block-by-default with an allowlist
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-18

### mfs-0571 — Microsoft 365

```text
https://www.safe365apps.com/accountselectionpage/c?c=f7f4c2ae-15da-43ec-b437-0035fb856bb8-176688b7-1fdd-4b32-a86c-c02b58f0b4d0
```

- **Domain:** `www.safe365apps.com`
- **Technique:** AiTM phishing-as-a-service portal replicating the Microsoft 'Pick an account' selection screen, victim keyed by GUID in the ?c= parameter
- **Detection:** Hunt URIs matching '/accountselection(page)?/c?c=<guid>' on any non-Microsoft host — same kit template as the365notify.com cluster; pivot on the GUID to find sibling victim links
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0572 — Microsoft 365

```text
https://www.safe365apps.com/accountselection/c?c=f7f4c2ae-15da-43ec-b437-0035fb856bb8
```

- **Domain:** `www.safe365apps.com`
- **Technique:** AiTM kit second-stage account-selection URL on the same safe365apps.com infrastructure (shorter ?c= victim token)
- **Detection:** Block apex safe365apps.com; generically flag lookalike domains combining 'safe/secure/verify' + '365' + 'apps/login/auth'
- **Source:** OpenPhish — https://github.com/openphish/public_feed/blob/main/feed.txt
- **Status:** active
- **First seen:** 2026-10-17

### mfs-0573 — Microsoft 365

```text
http://security.m365-microsoft.com/i/d51ee024a6cb3468996ec7c9307051d1d
```

- **Domain:** `security.m365-microsoft.com`
- **Technique:** Typosquat domain m365-microsoft.com with per-victim '/i/<32-hex>' tracking links; 'security.' subdomain used for account-security-alert lures
- **Detection:** Regex-hunt '/i/[0-9a-f]{32}' URI paths across proxy logs and sinkhole the whole m365-microsoft.com zone (security., support., emailnotifications., programme-hup. all observed)
- **Source:** Phishunt — https://phishunt.io/
- **Status:** active
- **First seen:** 2026-10-19

### mfs-0574 — Microsoft Outlook / Office 365

```text
http://outlook365livee.dothome.co.kr
```

- **Domain:** `outlook365livee.dothome.co.kr`
- **Technique:** Free Korean shared-hosting (dothome.co.kr) subdomain typosquat ('outlook365livee') serving an Outlook webmail sign-in clone
- **Detection:** Alert on *.dothome.co.kr and similar free-hosting wildcard zones where the subdomain label contains outlook/office/365/live — no legitimate business use in most environments
- **Source:** Phishunt — https://phishunt.io/
- **Status:** active
- **First seen:** 2026-10-19

### mfs-0575 — Microsoft 365 / Entra ID

```text
https://v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site
```

- **Domain:** `v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site`
- **Technique:** Typosquat domain mimicking the login.microsoftonline.com/common/oauth2 OpenID sign-in path, hosted on a cPanel default 'cpanel.site' hostname
- **Detection:** Alert on DNS/proxy requests to *.cpanel.site whose FQDN contains 'microsoftonline' or 'signin-openid'; cPanel default hostnames embed the server IP with dashes (129-121-112-148)
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0576 — Microsoft 365 / Outlook Web

```text
https://mail.v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site
```

- **Domain:** `mail.v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site`
- **Technique:** Mail-themed subdomain of the same microsoftonline-com-common-signin-openid typosquat kit on shared cPanel infrastructure
- **Detection:** Pivot on the parent domain microsoftonline-com-common-signin-openid[.]* via passive DNS — this actor spins up mail./v3sec. labels per target
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0577 — Microsoft 365

```text
https://www.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site
```

- **Domain:** `www.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site`
- **Technique:** Billing/licence-expiry lure on a long deceptive-label typosquat where 'login.microsoftonline' is placed in the subdomain, not the registrable domain
- **Detection:** Regex URL hostnames for 'login\.microsoftonline' NOT followed by '\.com$' — a legitimate Microsoft sign-in host always terminates at login.microsoftonline.com
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0578 — Microsoft 365

```text
https://jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site
```

- **Domain:** `jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site`
- **Technique:** Per-victim random 8-char subdomain prepended to the microsoftonline-billing-verification typosquat (wildcard DNS) for link-uniqueness and sandbox evasion
- **Detection:** Flag wildcard-DNS patterns: random 8-letter lowercase label + '.login.' + Microsoft-themed registrable domain; same kit on DigitalOcean IP 161.35.102.243
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0579 — Microsoft 365

```text
https://test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site
```

- **Domain:** `test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site`
- **Technique:** Operator test artifact of the same wildcard kit — 'test.' label stacked on the per-victim subdomain, confirming active kit development
- **Detection:** Hunt for 'test.' / 'dev.' labels prefixed to phishing wildcard hosts; these surface the kit's staging URLs before the campaign goes live
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0580 — Microsoft 365

```text
https://ttgyahvw.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site
```

- **Domain:** `ttgyahvw.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site`
- **Technique:** Second per-victim wildcard subdomain of the billing-verification typosquat kit on the same 161.35.102.243 host
- **Detection:** Block the whole registrable domain microsoftonline-billing-verification-secured-help rather than individual FQDNs; rotation is automated
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0581 — Microsoft 365

```text
https://www.zygzsdwh.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site
```

- **Domain:** `www.zygzsdwh.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site`
- **Technique:** Same kit on a second DigitalOcean node (104.248.114.136) with a 'www.' + random-label wildcard FQDN
- **Detection:** Correlate TLS SNI logs for cpanel.site certificates issued to Microsoft-keyword hostnames; Certificate Transparency shows the wildcard issuance burst
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0582 — Microsoft 365

```text
https://www.mxjkckus.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site
```

- **Domain:** `www.mxjkckus.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site`
- **Technique:** Microsoft billing-verification credential harvester, wildcard subdomain variant on 104.248.114.136
- **Detection:** Any inbound mail containing a URL whose hostname has 5+ dot-separated labels and includes 'microsoftonline' is high-confidence phish
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0583 — Microsoft 365

```text
https://orygozcb.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site
```

- **Domain:** `orygozcb.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site`
- **Technique:** Wildcard-DNS Microsoft 365 billing lure on shared cPanel hosting
- **Detection:** Blocklist the two IPs 161.35.102.243 and 104.248.114.136 — both serve only this Microsoft-impersonating kit
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0584 — Microsoft 365 / Azure

```text
http://microsoftcloudverification.com
```

- **Domain:** `microsoftcloudverification.com`
- **Technique:** Brand-keyword typosquat domain ('microsoft' + 'cloud verification') serving an account-verification credential prompt over plain HTTP
- **Detection:** Newly-registered-domain rules on registrable domains starting with 'microsoft' that are not in Microsoft's own CT/WHOIS footprint (MarkMonitor registrar)
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0585 — Microsoft OneDrive / Entra ID SSO

```text
https://sso.microsoft-onedrive.org
```

- **Domain:** `sso.microsoft-onedrive.org`
- **Technique:** 'sso.' subdomain on a hyphenated microsoft-onedrive typosquat to imitate a federated single-sign-on endpoint for a OneDrive share lure
- **Detection:** Flag hostnames with the label 'sso' or 'adfs' on any non-Microsoft-owned domain containing 'microsoft'; legitimate OneDrive SSO goes to login.microsoftonline.com only
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0586 — Microsoft Outlook

```text
https://outlookmails.de
```

- **Domain:** `outlookmails.de`
- **Technique:** ccTLD typosquat of Outlook webmail (.de) hosting a mailbox sign-in harvester
- **Detection:** Monitor CT logs for certificates on 'outlook*' registrable domains across ccTLDs; block at the apex since mail./www. variants follow
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0587 — Microsoft Outlook

```text
https://mail.outlookmails.de
```

- **Domain:** `mail.outlookmails.de`
- **Technique:** 'mail.' subdomain of the outlookmails.de typosquat, presenting a fake Outlook mailbox login
- **Detection:** Outbound POSTs to a host matching /outlook[a-z]*\.(de|fr|it|es)$/ with form fields named 'passwd'/'login' indicate credential submission
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0588 — Microsoft Outlook

```text
https://outlook-silk-nine.vercel.app
```

- **Domain:** `outlook-silk-nine.vercel.app`
- **Technique:** Free-hosting abuse — auto-generated Vercel subdomain (adjective-numeral naming) serving a cloned Outlook sign-in page
- **Detection:** Alert on *.vercel.app / *.netlify.app / *.pages.dev hostnames beginning with 'outlook', 'microsoft', 'onedrive' or 'login'; legitimate Microsoft never hosts auth on PaaS preview domains
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0589 — Microsoft Outlook

```text
https://outlook-ashy.vercel.app
```

- **Domain:** `outlook-ashy.vercel.app`
- **Technique:** Second Vercel-hosted Outlook sign-in clone from the same operator naming scheme ('outlook-<word>')
- **Detection:** Hunt proxy logs for Referer-less GETs to *.vercel.app followed by a POST — static-host phish kits exfiltrate to a Telegram/webhook endpoint on submit
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0590 — Microsoft 365

```text
https://m365-microsoft.com
```

- **Domain:** `m365-microsoft.com`
- **Technique:** Apex of the m365-microsoft[.]com typosquat used by an ongoing campaign that also rotates support./security./emailnotifications. subdomains with /i/<32-hex> per-victim tokens
- **Detection:** Block the registrable domain m365-microsoft[.]com outright; hunt URL paths matching '/i/[0-9a-f]{32,33}' as a per-recipient tracking token signature
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0591 — Microsoft 365

```text
https://microsoft-africa.org
```

- **Domain:** `microsoft-africa.org`
- **Technique:** Regional-branding typosquat ('Microsoft Africa') on .org, a TLD Microsoft does not use for tenant sign-in
- **Detection:** Flag 'microsoft-<region/country>' registrable domains; cross-check against Microsoft's authoritative domain list — all legitimate auth is on microsoft.com/microsoftonline.com/live.com
- **Source:** Phishunt — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0592 — Microsoft Office 365

```text
https://cocoonwoodsavoie.com/linkmyGod/office-3D8/index.php
```

- **Domain:** `cocoonwoodsavoie.com`
- **Technique:** Compromised legitimate WordPress site hosting an Office 365 PHP phishing kit in an attacker-created directory ('linkmyGod/office-3D8')
- **Detection:** Hunt web-proxy logs for '/index.php' under path segments containing 'office', 'o365' or 'owa' on otherwise unrelated business domains; kit directories are deployed via uploads/ or plugin RCE
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0593 — Microsoft Outlook

```text
https://f005.backblazeb2.com/file/reflrl/microsoft+outlook.html
```

- **Domain:** `f005.backblazeb2.com`
- **Technique:** Credential-harvesting HTML page hosted on abused Backblaze B2 public bucket (legit-cloud hosting for TLS/reputation)
- **Detection:** Alert on outbound requests to f005.backblazeb2.com/file/*/*.html where the object name contains microsoft|outlook|office|onedrive; most corporate users have no legitimate B2 file-serving traffic
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-10-25

### mfs-0594 — Microsoft 365

```text
https://microsoftconfig-3.vercel.app
```

- **Domain:** `microsoftconfig-3.vercel.app`
- **Technique:** Typosquat/brand-abuse landing page on free Vercel hosting; incrementing suffix indicates serial redeployment
- **Detection:** Hunt DNS/proxy for *.vercel.app hostnames containing microsoft|outlook|office|onedrive|m365, especially with numeric suffixes (-1,-2,-3) that signal takedown-resistant redeploys
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-10-25

### mfs-0595 — Microsoft Outlook

```text
https://outlook-phi-one.vercel.app
```

- **Domain:** `outlook-phi-one.vercel.app`
- **Technique:** Fake Outlook sign-in page on Vercel free tier; Vercel auto-generated three-word subdomain pattern
- **Detection:** Flag newly observed *.vercel.app domains whose first label starts with outlook-/microsoft-; correlate with first-seen <7 days in passive DNS
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-10-24

### mfs-0596 — Microsoft Outlook

```text
https://grn-microsoft-outlook.vercel.app
```

- **Domain:** `grn-microsoft-outlook.vercel.app`
- **Technique:** Brand-stacked typosquat (multiple Microsoft brand tokens in one label) on Vercel
- **Detection:** Score hostnames by count of Microsoft brand tokens (microsoft+outlook+office) in a single DNS label — two or more on a non-microsoft.com apex is near-certain phishing
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-10-24

### mfs-0597 — Microsoft 365

```text
https://msauth.biz
```

- **Domain:** `msauth.biz`
- **Technique:** Fake M365 login page (DigitalOcean-hosted) reached via hidden link in a PDF delivered through legitimate Frame.io share notifications, with a Cloudflare Pages hop — campaign 'Phantom Preview'
- **Detection:** Block/alert on msauth.* outside microsoft.com; hunt inbound mail from Frame.io notification senders containing PDF attachments with embedded outbound links, and newly registered domains mimicking Microsoft auth hostnames (msauth, msonline, msftauth)
- **Source:** Ocean Security (via Hackread) — https://hackread.com/scammers-frame-io-steal-microsoft-365-credentials/
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0598 — Microsoft Teams

```text
https://teams-online.com
```

- **Domain:** `teams-online.com`
- **Technique:** Typosquat domain cloning the full Microsoft Teams sign-in interface; flagged four days after registration
- **Detection:** Add to tenant block list and web filtering; hunt for teams-* / *-teams apex domains registered in the last 30 days resolving outside Microsoft ASNs
- **Source:** Steven Lim (@0x534c) via CyberSecurityNews — https://cybersecuritynews.com/domain-with-exact-microsoft-teams-interface/
- **Status:** active
- **First seen:** 2026-10-08

### mfs-0599 — Microsoft 365

```text
https://dv0psh-purv3w-azfn-b2c0-msauth3-m365svc-s3ntln-4zrfn3x-cntnrx.workers.dev
```

- **Domain:** `dv0psh-purv3w-azfn-b2c0-msauth3-m365svc-s3ntln-4zrfn3x-cntnrx.workers.dev`
- **Technique:** Wazza phishing kit — OAuth device-code phishing landing page on Cloudflare Workers; leetspeak Microsoft/Azure service tokens in a long hyphenated subdomain
- **Detection:** Alert on *.workers.dev hostnames with 5+ hyphen-delimited labels containing leetspeak Microsoft service strings (m365s, msauth, azfn, s3ntln, purv3, 0ffc3); pair with Entra ID sign-in logs showing authenticationProtocol=deviceCode from unexpected ASNs
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0600 — Microsoft 365

```text
https://ssosvc-m365s-kvl-dv0pshb-s3ntln-c0mply-4zrmonx-apimgwx-evnthb.workers.dev
```

- **Domain:** `ssosvc-m365s-kvl-dv0pshb-s3ntln-c0mply-4zrmonx-apimgwx-evnthb.workers.dev`
- **Technique:** Wazza kit device-code phishing landing page on Cloudflare Workers (SSO-themed leetspeak subdomain)
- **Detection:** Block *.workers.dev by default for user browsing; hunt proxy logs for first-label matches on ssosvc|m365s|msauth|entr tokens
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0601 — Microsoft 365 / Office

```text
https://wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev
```

- **Domain:** `wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev`
- **Technique:** Wazza kit device-code phishing landing page on Cloudflare Workers; also used as a parent for randomized victim-specific subdomains
- **Detection:** Treat any workers.dev hostname with a random 5-label prefix over a Microsoft-token parent as malicious; wildcard-block the parent, not just the observed FQDN
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0602 — Microsoft 365 / Teams / Intune

```text
https://purv3w3-t3ms4pp-certs-intun3-sbussvx-4zredg-siemsv-pip3ln-0ffc3.workers.dev
```

- **Domain:** `purv3w3-t3ms4pp-certs-intun3-sbussvx-4zredg-siemsv-pip3ln-0ffc3.workers.dev`
- **Technique:** Wazza kit device-code phishing landing page on Cloudflare Workers (Teams/Intune-themed leetspeak subdomain)
- **Detection:** Regex proxy logs for workers.dev labels matching t3ms|intun3|0ffc3|purv3 — leetspeak digit substitution of Microsoft product names is a high-fidelity kit fingerprint
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0603 — Microsoft OneDrive / Microsoft 365

```text
https://c5id-pc17-fffoub1-bul3-ahv1-r00kubt.ondrv-pwrbi3-s3ntln-quesvxs-l0gsvx-entr-m365s-cmplncx-ehubn.workers.dev
```

- **Domain:** `c5id-pc17-fffoub1-bul3-ahv1-r00kubt.ondrv-pwrbi3-s3ntln-quesvxs-l0gsvx-entr-m365s-cmplncx-ehubn.workers.dev`
- **Technique:** Wazza kit per-victim randomized subdomain over a OneDrive/Entra-themed Cloudflare Workers parent; device-code flow
- **Detection:** Wildcard-block *.ondrv-pwrbi3-s3ntln-quesvxs-l0gsvx-entr-m365s-cmplncx-ehubn.workers.dev; the per-victim prefix rotates so FQDN-only blocking fails
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0604 — Microsoft 365 / Azure

```text
https://d3m9a-goo2ns-wx0g-jzhuc2-t9r2b9i.dvps-azbl-fnapp-trc3svc-synpx-quesvxs-purv3-siemsvx-cmplncx.workers.dev
```

- **Domain:** `d3m9a-goo2ns-wx0g-jzhuc2-t9r2b9i.dvps-azbl-fnapp-trc3svc-synpx-quesvxs-purv3-siemsvx-cmplncx.workers.dev`
- **Technique:** Wazza kit per-victim randomized subdomain over an Azure-service-themed Workers parent; device-code credential/token theft
- **Detection:** Wildcard-block the parent label set; alert in Entra ID on device-code sign-ins where the originating IP has no prior history for the tenant
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0605 — Microsoft 365 / Office

```text
https://unhf69e-e0ppo-l0qoo-a12bcfj-ig1sa4v.wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev
```

- **Domain:** `unhf69e-e0ppo-l0qoo-a12bcfj-ig1sa4v.wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev`
- **Technique:** Wazza kit per-victim randomized subdomain over the Windows/Office-themed Workers parent; device-code phishing
- **Detection:** Correlate workers.dev DNS lookups with a Microsoft device-code sign-in in the same session window — the pairing is the strongest signal for this kit
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0606 — Microsoft 365

```text
https://fgwhjmdaurspxvznk.hutspotmaken.eu/B4fWRuA
```

- **Domain:** `fgwhjmdaurspxvznk.hutspotmaken.eu`
- **Technique:** Wazza kit preloader/redirector on a compromised .eu site (random 17-char subdomain + short path) that hands off to the M365 device-code landing page
- **Detection:** Flag HTTP GETs to random high-entropy subdomains of legitimate .eu domains with short alphanumeric paths; block the Wazza .eu redirector set (hutspotmaken.eu, beton-beton.eu, bike-msca.eu, cardamomo.eu, diabetesnet.eu et al.)
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0607 — Microsoft 365 / OneDrive

```text
https://sites.google.com/view/onwajuly/home
```

- **Domain:** `sites.google.com`
- **Technique:** Google Sites staging page used as the first hop in the Wazza chain (abuses google.com reputation) before redirecting to the M365 device-code landing page
- **Detection:** Alert on sites.google.com/view/* URLs arriving via external email with random or nonsense slugs; legitimate business use is rare and easy to allowlist by slug
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0608 — Microsoft 365

```text
https://sites.google.com/view/securespdf/home
```

- **Domain:** `sites.google.com`
- **Technique:** Google Sites 'secure PDF' lure page in the Wazza chain; PDF-document theme leading to a fake M365 authentication step
- **Detection:** Hunt mail bodies for sites.google.com/view links with document-themed slugs (securespdf, securedoc, viewpdf) combined with a PDF attachment lure
- **Source:** LevelBlue SpiderLabs — https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0609 — Microsoft OneDrive

```text
http://creyt.cl/centennialcws/onedrive-verify-obf.html
```

- **Domain:** `creyt.cl`
- **Technique:** Compromised legitimate .cl site hosting a static HTML 'Access your file - OneDrive' document lure that pivots to a credential form
- **Detection:** Hunt proxy logs for .html GETs under /centennialcws/ or any *-verify-obf.html filename on non-Microsoft hosts; alert on HTML page titles containing 'OneDrive' served from a non-microsoft.com/sharepoint.com origin
- **Source:** phishunt.io (confirmed live, page title 'Access your file - OneDrive') — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0610 — Microsoft SharePoint Online

```text
http://sharepointonline-microsoft.com/?normal=l8AhRCc
```

- **Domain:** `sharepointonline-microsoft.com`
- **Technique:** Brand-concatenation typosquat domain with a per-victim 'normal' tracking token in the query string
- **Detection:** Alert on DNS/TLS SNI for registered domains that concatenate two Microsoft product strings (sharepointonline + microsoft) outside of *.microsoft.com; flag single-param query keys like ?normal= on first-seen domains
- **Source:** OpenPhish community feed — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0611 — Microsoft

```text
http://www.microsofl.compras-ok.com/
```

- **Domain:** `www.microsofl.compras-ok.com`
- **Technique:** Homoglyph typosquat (microsofl ← microsoft) run as a subdomain on a multi-brand phishing-as-a-service host that also serves bank lures
- **Detection:** Run Levenshtein distance <=1 against 'microsoft' over subdomain labels in DNS logs; pivot on the parent domain compras-ok.com — any subdomain under it is hostile
- **Source:** OpenPhish community feed — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0612 — Microsoft Outlook

```text
https://microsoftoutlook.flazio.online/
```

- **Domain:** `microsoftoutlook.flazio.online`
- **Technique:** Free website-builder (Flazio) subdomain hosting an Outlook sign-in clone — abuses a trusted SaaS parent domain and valid wildcard TLS
- **Detection:** Alert on any *.flazio.online hostname whose label contains a Microsoft product string; more broadly, treat brand-keyword subdomains on site-builder platforms (flazio, weebly, dothome, blogspot) as high-risk
- **Source:** OpenPhish community feed — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0613 — Microsoft 365

```text
https://microsoft0117.vercel.app
```

- **Domain:** `microsoft0117.vercel.app`
- **Technique:** Vercel-hosted static sign-in clone using a numeric-suffix throwaway project name for rapid redeployment
- **Detection:** Hunt *.vercel.app hostnames matching ^microsoft[0-9]+ or ^outlook/onedrive + digits; Vercel/Netlify/Pages subdomains should never host Microsoft-branded auth forms
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0614 — Microsoft OneDrive

```text
https://onedrive-1-one.vercel.app
```

- **Domain:** `onedrive-1-one.vercel.app`
- **Technique:** Vercel-hosted OneDrive document-share lure; same naming family as the previously tracked onedrive-4-nine.vercel.app
- **Detection:** Regex *.vercel.app for ^onedrive-[0-9]+-(one|two|nine|...)$ — the word-number pattern is a reusable kit template; block the whole family, not single hosts
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0615 — Microsoft OneDrive

```text
https://wahat-ipp.sa-onedrive.com
```

- **Domain:** `wahat-ipp.sa-onedrive.com`
- **Technique:** Lookalike apex domain (sa-onedrive.com) with per-target subdomain, suggesting Saudi/regional org-specific credential harvesting
- **Detection:** Block the apex sa-onedrive.com and wildcard its subdomains; hunt newly registered domains containing 'onedrive' with a two-letter country prefix (sa-, uk-, ae-)
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0616 — Microsoft Outlook

```text
http://validar-micuenta-outlook.yzz.me
```

- **Domain:** `validar-micuenta-outlook.yzz.me`
- **Technique:** Spanish-language 'validate my account' Outlook lure on free yzz.me dynamic-DNS hosting; sibling of the tracked login-outlook365.yzz.me
- **Detection:** Blanket-block *.yzz.me at DNS — the provider is overwhelmingly abused; separately alert on Spanish verbs (validar, verificar, reactivar) adjacent to Microsoft brand tokens in hostnames
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0617 — Microsoft 365 / Entra ID

```text
https://microsoft-online.gr
```

- **Domain:** `microsoft-online.gr`
- **Technique:** ccTLD typosquat imitating login.microsoftonline.com via a hyphenated .gr registration
- **Detection:** Alert on any resolved domain matching microsoft[-_]?online under a ccTLD other than .com; legitimate Microsoft auth only terminates at login.microsoftonline.com / login.microsoft.com
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0618 — Microsoft

```text
http://microsoft-telemetry.at
```

- **Domain:** `microsoft-telemetry.at`
- **Technique:** IT-support/telemetry-themed lookalike domain used as a pretext landing page before credential capture
- **Detection:** Flag outbound HTTP to hyphenated microsoft-* apex domains on European ccTLDs; genuine Microsoft telemetry endpoints live under *.microsoft.com, *.events.data.microsoft.com — never a bare ccTLD
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0619 — Microsoft Outlook

```text
https://outlook.us.org
```

- **Domain:** `outlook.us.org`
- **Technique:** Free-subdomain-provider squat — 'outlook' registered as a label under the us.org shared zone to look like an official Outlook host
- **Detection:** Treat brand-named labels under free subdomain registrars (us.org, eu.org, yzz.me, dothome.co.kr) as phishing by default; alert on HTTP Host headers of 'outlook.<anything-not-microsoft>'
- **Source:** phishunt.io — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0620 — Microsoft 365 / Entra ID

```text
https://beacon-surge-sync.workers.dev
```

- **Domain:** `beacon-surge-sync.workers.dev`
- **Technique:** Cloudflare Workers relay for the 'Wazza' OAuth device-code phishing kit — victim enters the attacker's code at microsoft.com/devicelogin, tokens are exfiltrated through this worker
- **Detection:** You cannot block *.workers.dev wholesale, so match at hostname level in proxy logs; pair with Entra sign-in log hunting for authenticationProtocol = deviceCode from unexpected IPs/user agents
- **Source:** Security Arsenal / AlienVault OTX pulse analysis (Wazza device code phishing kit) — https://securityarsenal.com/blog/wazza-device-code-phishing-kit-gcp-llmjacking-campaign-otx-pulse-analysis-microsoft-365-and-cloud-credential-theft-detection-pack
- **Status:** active
- **First seen:** 2026-10-21

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["onmicrosoftonline-mmscrmcustomers.mm.am", "site.com-microsoftonline-ondrive.ca", "notifications.microsoft-ssl.com", "click2.microsoftsupportcenter.digital", "login-outlook365.yzz.me", "microsoft-alpha.vercel.app", "outlook-serv-coral.vercel.app", "onedrive-4-nine.vercel.app", "www.onedrive-4-nine.vercel.app", "network-office-cm51.bolt.host", "namastespa.ca", "microsoftwordob.blogspot.com", "n2cknem.github.io", "outlook-login.github.io", "office365.internal-alerts.com", "support.m365-microsoft.com", "programme-hup.m365-microsoft.com", "emailnotifications.m365-microsoft.com", "office365.rricrosoft-offices.org", "security.email-microsoft.com", "auth.properties", "outlook.webaccess-alert.com", "outlook.verifytoken.com", "onedrive.at-us.therelayservice.com", "81.190.202.64.host.secureserver.net", "www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "reactivar-microsoft-live.iceiy.com", "outlook-email-2026.hstn.me", "0365-microsoft.gitbook.io", "401283-outlookmailbox-00012-validate.weebly.com", "microsoft.citrix-sharing.com", "plugins.sugar-outlook.com", "microsoft-sharepoint.fr", "microsoft365updates.com", "microsoft365businessbasic.com", "office365licensingsupport.com", "csp.microsoftsupportcenter.digital", "microsoft-se.us", "microsoftuk.co", "microsoftpl.biz.pl", "microsoftjk.eu.org", "microsoft.updata.net.cn", "outlookmail.social", "office.rox-klimatechnik.sbs", "mslogin.oauth-live.com", "login.oauth-live.com", "teams-cloud.live", "amgen.teams-cloud.live", "abcgil.com", "dayoadeyemo.com", "f005.backblazeb2.com", "spazioaperto-shared-document.live-document-mcs365980.workers.dev", "www.safe365apps.com", "www.safe365apps.com", "security.m365-microsoft.com", "outlook365livee.dothome.co.kr", "v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site", "mail.v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site", "www.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "ttgyahvw.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "www.zygzsdwh.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "www.mxjkckus.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "orygozcb.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "microsoftcloudverification.com", "sso.microsoft-onedrive.org", "outlookmails.de", "mail.outlookmails.de", "outlook-silk-nine.vercel.app", "outlook-ashy.vercel.app", "m365-microsoft.com", "microsoft-africa.org", "cocoonwoodsavoie.com", "f005.backblazeb2.com", "microsoftconfig-3.vercel.app", "outlook-phi-one.vercel.app", "grn-microsoft-outlook.vercel.app", "msauth.biz", "teams-online.com", "dv0psh-purv3w-azfn-b2c0-msauth3-m365svc-s3ntln-4zrfn3x-cntnrx.workers.dev", "ssosvc-m365s-kvl-dv0pshb-s3ntln-c0mply-4zrmonx-apimgwx-evnthb.workers.dev", "wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev", "purv3w3-t3ms4pp-certs-intun3-sbussvx-4zredg-siemsv-pip3ln-0ffc3.workers.dev", "c5id-pc17-fffoub1-bul3-ahv1-r00kubt.ondrv-pwrbi3-s3ntln-quesvxs-l0gsvx-entr-m365s-cmplncx-ehubn.workers.dev", "d3m9a-goo2ns-wx0g-jzhuc2-t9r2b9i.dvps-azbl-fnapp-trc3svc-synpx-quesvxs-purv3-siemsvx-cmplncx.workers.dev", "unhf69e-e0ppo-l0qoo-a12bcfj-ig1sa4v.wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev", "fgwhjmdaurspxvznk.hutspotmaken.eu", "sites.google.com", "sites.google.com", "creyt.cl", "sharepointonline-microsoft.com", "www.microsofl.compras-ok.com", "microsoftoutlook.flazio.online", "microsoft0117.vercel.app", "onedrive-1-one.vercel.app", "wahat-ipp.sa-onedrive.com", "validar-micuenta-outlook.yzz.me", "microsoft-online.gr", "microsoft-telemetry.at", "outlook.us.org", "beacon-surge-sync.workers.dev"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

