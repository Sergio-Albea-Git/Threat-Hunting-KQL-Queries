# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 126
- **Retention:** rolling 30 days
- **Last updated:** 2026-10-24
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
| mfs-0439 | Microsoft 365 / Entra ID | Credential harvester on a compromised legitimate host, faking an OAuth authorize request with a capital-I 'redirect_urI' parameter pointing at login.microsoftonline.com | 2026-09-25 | OpenPhish + PhishTank (via phishunt.io) |
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

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["wildlands.acltci.com", "authentication.ms", "publicofficeoutlooknotificationscry-dpkjhfszqaa2.edgeone.dev", "security-server-page--sheryln1990.replit.app", "security-server--tabbielynn.replit.app", "security-server-page--servarog.replit.app", "microsoft0117.vercel.app", "creyt.cl", "clovdmicrsotfmailaamkagmxn2uxywe.klassik-erh.de", "microsoft-online.gr", "microsoftoffice-o365.com", "www.miccrossofteam.top", "www.connexioncompteoutlook.weebly.com", "verificarcuenta-micros0ft2026way.zya.me", "microsoft-office365.site", "microsoftsteam.live", "forms-microsoft.com", "login-microsoft-verify.online", "microsoft-account.live", "microsoft-key.online", "office365plus.net", "microsofteamsinvite.top", "hotmailli.site", "outlookinboxmessage.com", "microsofteamsinvite.live", "teams-microsofts-meet.com", "teams-microsoft-downloads.com", "outlook.surf", "onedriveshare.net", "onedrivecloud.net", "microsoft-windows-support.com", "microsoft-onedrive.org", "inbox-microsoft.com", "0nedrive.space", "salessupport-microsoft.com", "protect-outlook.com", "outlookaccessportal.com", "com-onedrive.com", "outlook.evergreenfin.ltd", "micr0s0ft0ffice365.com", "microsoftonlinesm.top", "com-microsoft-onedrive.live", "outlookk.site", "outlook-email-primecaretech.com", "microsoftfile.xyz", "microsoftpro.top", "microsoftplus.com", "microsoftolnine.com", "microsoftentraconnect.com", "microsoftteamupdate.com", "microsoftofficeph.com", "0nedrive.online", "onmicrosoftonline-mmscrmcustomers.mm.am", "site.com-microsoftonline-ondrive.ca", "notifications.microsoft-ssl.com", "click2.microsoftsupportcenter.digital", "login-outlook365.yzz.me", "microsoft-alpha.vercel.app", "outlook-serv-coral.vercel.app", "onedrive-4-nine.vercel.app", "www.onedrive-4-nine.vercel.app", "network-office-cm51.bolt.host", "namastespa.ca", "microsoftwordob.blogspot.com", "n2cknem.github.io", "outlook-login.github.io", "office365.internal-alerts.com", "support.m365-microsoft.com", "programme-hup.m365-microsoft.com", "emailnotifications.m365-microsoft.com", "office365.rricrosoft-offices.org", "security.email-microsoft.com", "auth.properties", "outlook.webaccess-alert.com", "outlook.verifytoken.com", "onedrive.at-us.therelayservice.com", "81.190.202.64.host.secureserver.net", "www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "reactivar-microsoft-live.iceiy.com", "outlook-email-2026.hstn.me", "0365-microsoft.gitbook.io", "401283-outlookmailbox-00012-validate.weebly.com", "microsoft.citrix-sharing.com", "plugins.sugar-outlook.com", "microsoft-sharepoint.fr", "microsoft365updates.com", "microsoft365businessbasic.com", "office365licensingsupport.com", "csp.microsoftsupportcenter.digital", "microsoft-se.us", "microsoftuk.co", "microsoftpl.biz.pl", "microsoftjk.eu.org", "microsoft.updata.net.cn", "outlookmail.social", "office.rox-klimatechnik.sbs", "mslogin.oauth-live.com", "login.oauth-live.com", "teams-cloud.live", "amgen.teams-cloud.live", "abcgil.com", "dayoadeyemo.com", "f005.backblazeb2.com", "spazioaperto-shared-document.live-document-mcs365980.workers.dev", "www.safe365apps.com", "www.safe365apps.com", "security.m365-microsoft.com", "outlook365livee.dothome.co.kr", "v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site", "mail.v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site", "www.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "ttgyahvw.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "www.zygzsdwh.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "www.mxjkckus.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "orygozcb.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "microsoftcloudverification.com", "sso.microsoft-onedrive.org", "outlookmails.de", "mail.outlookmails.de", "outlook-silk-nine.vercel.app", "outlook-ashy.vercel.app", "m365-microsoft.com", "microsoft-africa.org", "cocoonwoodsavoie.com"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

