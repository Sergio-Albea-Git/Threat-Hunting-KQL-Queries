# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 354
- **Retention:** rolling 30 days
- **Last updated:** 2026-11-10
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
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
| mfs-0621 | Microsoft 365 | Typosquat homoglyph domain ('miicro67soft') hosting a cloned Microsoft sign-in page on free Vercel hosting | 2026-11-02 | PhishTank |
| mfs-0622 | Microsoft 365 | Free Weebly site-builder page serving a fake Microsoft/Office credential form | 2026-11-01 | PhishTank |
| mfs-0623 | Microsoft 365 | Random-string Weebly subdomain hosting a Microsoft sign-in clone (same kit cluster as oosoftlms) | 2026-11-01 | PhishTank |
| mfs-0624 | Microsoft 365 | Replit-hosted 'security server' lure redirecting to a fake Microsoft login (note 'danlel' = Daniel typosquat) | 2026-10-31 | PhishTank |
| mfs-0625 | Microsoft 365 | Misspelled 'admin-suport-update' Weebly page impersonating a Microsoft 365 admin/account update portal | 2026-10-31 | PhishTank |
| mfs-0626 | Microsoft | Typosquat of microsoft.com with an appended 'h' (microsofth[.]com), wildcard subdomains mimicking real Microsoft service hostnames | 2026-10-31 | phishunt.io |
| mfs-0627 | Microsoft Entra ID | Typosquat subdomain posing as a Microsoft authentication endpoint (auth.microsofth[.]com) | 2026-10-31 | phishunt.io |
| mfs-0628 | Microsoft 365 | Typosquat subdomain mimicking the Microsoft 365 app launcher (apps.microsoft.com lookalike) | 2026-10-31 | phishunt.io |
| mfs-0629 | Microsoft Azure | Typosquat subdomain impersonating the Azure portal on microsofth[.]com | 2026-10-31 | phishunt.io |
| mfs-0630 | Microsoft 365 | Typosquat subdomain imitating Microsoft's cloud.microsoft first-party domain | 2026-10-31 | phishunt.io |
| mfs-0631 | Microsoft | Deceptive 'com.' label so the hostname reads like microsoft.com in truncated mobile address bars | 2026-10-31 | phishunt.io |
| mfs-0632 | Microsoft | Typosquat subdomain on the microsofth[.]com phishing wildcard infrastructure | 2026-10-31 | phishunt.io |
| mfs-0633 | Microsoft | Typosquat subdomain impersonating dotnet.microsoft.com developer portal | 2026-10-31 | phishunt.io |
| mfs-0634 | Microsoft Edge | Typosquat subdomain posing as an Edge browser/update page — likely update-lure to credential or payload | 2026-10-31 | phishunt.io |
| mfs-0635 | Microsoft Power Automate | Typosquat subdomain impersonating flow.microsoft.com (Power Automate) sign-in | 2026-10-31 | phishunt.io |
| mfs-0636 | Microsoft 365 | Replit-hosted fake Microsoft security-alert sign-in page; same kit/naming scheme as the 'security-server-*' cluster | 2026-10-30 | PhishTank |
| mfs-0637 | Microsoft 365 | Webflow-hosted landing page cloning the Microsoft sign-in experience | 2026-10-30 | PhishTank |
| mfs-0638 | Microsoft OneDrive | Targeted typosquat (en-onedrive[.]com) with a victim-company subdomain serving a fake OneDrive document-share sign-in | 2026-10-30 | phishunt.io |
| mfs-0639 | Microsoft Outlook | Outlook typosquat on a cheap .cc TLD hosting a webmail credential form | 2026-10-30 | phishunt.io |
| mfs-0640 | Microsoft 365 | Compromised Bluehost staging/temp hostname (*.mybluehost.me) repurposed to host a Microsoft credential-harvest page | 2026-10-28 | PhishTank |
| mfs-0641 | Microsoft 365 | Plain-HTTP variant of the same compromised Bluehost staging host serving the Microsoft sign-in clone | 2026-10-28 | PhishTank |
| mfs-0642 | Microsoft 365 | Tencent EdgeOne Pages (*.edgeone.dev) free edge hosting with a randomised subdomain fronting a fake Microsoft login | 2026-10-28 | PhishTank |
| mfs-0643 | Microsoft 365 | Wasmer Edge hosting a 'Microfis' (Microsoft typosquat) password-recovery / password-reset credential lure | 2026-10-28 | PhishTank |
| mfs-0644 | Microsoft 365 | French-language 'document portal' lure impersonating a company's Microsoft 365 document share, hosted on Vercel | 2026-10-24 | PhishTank |
| mfs-0645 | Microsoft 365 | Chained Google open-redirect (plusone.google.com/url?q= → google.com/goto?url=) delivering victims to a fake Microsoft sign-in page | 2026-10-23 | PhishTank |
| mfs-0646 | Microsoft 365 | Compromised/abused .shop e-commerce domain repurposed as a Microsoft credential-harvest landing page | 2026-10-23 | PhishTank |
| mfs-0647 | Microsoft 365 | Laravel Cloud hosting with a base64/JWT-encoded path embedding campaignId and victim email — per-recipient pre-filled Microsoft phish | 2026-10-23 | PhishTank |
| mfs-0648 | Microsoft 365 | Disposable .click domain with a random-looking label serving a Microsoft sign-in clone | 2026-10-21 | PhishTank |
| mfs-0649 | Microsoft 365 | Compromised legitimate site hosting a phish kit whose unrendered {{randomVIII}} template token leaked into the live URL | 2026-10-21 | PhishTank |
| mfs-0650 | Microsoft 365 | Vercel auto-generated '<word>-<colour>' project subdomain hosting a Microsoft credential page | 2026-10-21 | PhishTank |
| mfs-0652 | Microsoft Office 365 | Compromised corporate website hosting a static HTML Office 365 credential-harvest page in an uploaded '/pronto_office/' kit directory | 2026-11-02 | OpenPhish |
| mfs-0653 | Microsoft SharePoint | SharePoint 'document notification' lure on Vercel, served over plain HTTP, leading to a Microsoft sign-in prompt | 2026-11-02 | OpenPhish |
| mfs-0654 | Microsoft 365 | Fake 'My Office 365' online payment/billing form harvesting card + account data (GoDaddy-registered, AWS-hosted) | 2026-11-01 | PhishDestroy (DestroyList) |
| mfs-0655 | Microsoft Office 365 | Firebase *.web.app free-hosting credential page with 'Redirecting.....' cloaking that bounces non-targets to Google Search | 2026-11-01 | PhishDestroy (DestroyList) |
| mfs-0656 | Microsoft Office 365 | Firebase-hosted Office 365 lookalike using redirect-to-Google cloaking to evade sandboxes | 2026-11-01 | PhishDestroy (DestroyList) |
| mfs-0657 | Microsoft Outlook / Exchange OWA | Fake Outlook Web Access authentication page (page title 'Outlookionos-webmail') on Firebase hosting | 2026-11-01 | PhishDestroy (DestroyList) |
| mfs-0658 | Microsoft Office / Microsoft 365 | Weebly free-site 'Microsoft Office Account' form abusing a fake 'Encourage Multi-Factor Authenticator (EMFA)' pretext to collect name, school email, password and phone | 2026-11-01 | PhishDestroy (DestroyList) |
| mfs-0659 | Microsoft | Typosquat (microsoftonline → microsoftoniine, l→i homoglyph) on .my ccTLD; registered 2026-10-10, parked ~9.5h after detection | 2026-11-01 | PhishDestroy / Spamhaus DBL / SEAL |
| mfs-0660 | Microsoft Outlook | Subdomain spoof ('outlook.' prefix on an unrelated apex) serving a credential page behind a Cloudflare access challenge | 2026-11-01 | PhishDestroy (DestroyList) |
| mfs-0661 | Microsoft 365 / Azure AD (Entra ID) | ccTLD lookalike of login.microsoftonline.com (hyphen-swap for the dot); nazwa.pl registrar, hosted 85.128.128.104 Krakow — still confirmed live 2026-11-01 | 2026-11-01 | PhishDestroy / Spamhaus DBL / AlienVault OTX |
| mfs-0662 | Microsoft Office 365 | Spanish-language fake 'Iniciar sesion' Microsoft login on Vercel; urlscan exposed JS globals 'discordWebhook' and 'adminPassword' — credentials exfiltrated via Discord webhook. Still active 2026-11-01 | 2026-11-01 | PhishDestroy / Google Safe Browsing |
| mfs-0663 | Microsoft | Typosquat (micronosoft) hosting a Microsoft-service subdomain farm — login.micronosoft.com and teams.micronosoft.com — with HTTP 302 redirect chain; last active 2026-11-01 | 2026-11-01 | PhishDestroy / MetaMask / SEAL |
| mfs-0664 | Microsoft Outlook | Impersonation-class Outlook phishing on Cloudflare CDN (London); NameCheap registration 2026-06-23, TLS valid to 2027-01-17 | 2026-10-26 | PhishDestroy / AlienVault OTX |
| mfs-0665 | Microsoft 365 | Vercel-hosted static credential harvester — generic "Welcome Back!" page with Microsoft-branded sign-in form posting creds to an attacker endpoint | 2026-11-03 | phishunt.io (also in OpenPhish public feed) |
| mfs-0666 | Microsoft Teams / SharePoint Online | Combosquat domain (microsoftonline-sharepoint[.]online) serving a "Teams Meeting - Join Now" lure that funnels to credential capture | 2026-11-02 | phishunt.io |
| mfs-0667 | Microsoft | Typosquat/brand-impersonation domain serving a fake "Microsoft | Regional Endpoint — Turkey" gate page used as a first-stage redirector to sign-in phish | 2026-11-02 | phishunt.io |
| mfs-0668 | Microsoft | Sibling typosquat of microsoftturkey[.]com — identical "Microsoft | Regional Endpoint — Turkey" gate page (same 1452-byte payload), indicating one actor-controlled cluster | 2026-11-02 | phishunt.io |
| mfs-0669 | Microsoft OneDrive | HTML credential-phish page ("OneDrive — Secure Document Access") hosted behind an ngrok tunnel to rotate infrastructure and dodge domain takedowns | 2026-10-31 | phishunt.io |
| mfs-0670 | Microsoft SharePoint / Outlook | Vercel-hosted SharePoint document lure that exfiltrates captured credentials via the EmailJS SaaS API, then redirects the victim to the real https://outlook.live.com/ to mask the theft | 2026-11-03 | OpenPhish (public feed) |
| mfs-0671 | Microsoft Outlook Web App (OWA) / Exchange | Lookalike domain hosting a fake OWA /owa/ sign-in path behind Cloudflare; now serving Cloudflare's own "Suspected Phishing" interstitial, confirming the verdict | 2026-11-03 | OpenPhish (public feed) |
| mfs-0672 | Microsoft (login page) | Free GitHub Pages hosting of a cloned Microsoft sign-in page (page title literally "Microsoft login page") — abuse of a trusted, TLS-valid, high-reputation domain | 2026-11-03 | OpenPhish (public feed) |
| mfs-0673 | Microsoft Office 365 | Firebase-hosted dynamic open-redirector: obfuscated JS polls api.telegram.org/bot<token>/getUpdates to pull the current phishing destination at runtime, falling back to a benign Google search if the bot is dead | 2026-11-01 | PhishDestroy |
| mfs-0674 | Microsoft Outlook / Microsoft 365 | Credential-harvesting fake Outlook sign-in hosted on free Vercel subdomain | 2026-11-05 | phishunt.io |
| mfs-0675 | Microsoft SharePoint / OneDrive | Static OneDrive.html credential page tunnelled through ngrok reverse proxy | 2026-11-05 | phishunt.io |
| mfs-0676 | Microsoft Hotmail / Outlook.com | Typosquat brand domain serving fake Hotmail/Outlook logon | 2026-11-04 | phishunt.io |
| mfs-0677 | Microsoft Hotmail / Outlook.com | Sibling subdomain of hotmail666[.]com phishing cluster | 2026-11-04 | phishunt.io |
| mfs-0678 | Microsoft 365 | Homoglyph/typosquat 'o356' (Office 365) with per-victim random path token | 2026-11-04 | phishunt.io |
| mfs-0679 | Microsoft Outlook | Fake Outlook signin endpoint with JWT-style ?t= victim token (AiTM-style prefilled email) | 2026-11-03 | phishunt.io |
| mfs-0682 | Microsoft Office / Microsoft 365 | ClickFix fake 'verify you are human' page on single-letter typosquat (microsoftofice) leading to RAT via Windows Run dialog | 2026-11-03 | Security Boulevard / CyberProof research |
| mfs-0683 | Microsoft Office / Microsoft 365 | Credential/password page on the microsoftofice[.]cz lookalike IT-department infrastructure | 2026-11-03 | Security Boulevard / CyberProof research |
| mfs-0684 | Microsoft Entra ID / microsoftonline | Newly registered combosquat of login.microsoftonline.com for sign-in harvesting | 2026-11-04 | phishunt.io (newly registered) |
| mfs-0685 | Microsoft Entra ID | Newly registered auth-themed combosquat on .app TLD | 2026-11-04 | phishunt.io (newly registered) |
| mfs-0686 | Microsoft Entra ID / microsoftonline | Character-drop typosquat of 'microsoftonline' (missing 'nl') | 2026-11-04 | phishunt.io (newly registered) |
| mfs-0687 | Microsoft 365 support | Tech-support themed lookalike used for sign-in and callback lures | 2026-11-04 | phishunt.io (newly registered) |
| mfs-0688 | Microsoft 365 | API-themed combosquat posing as Microsoft 365 service endpoint | 2026-11-04 | phishunt.io (newly registered) |
| mfs-0689 | Microsoft | Cheap-TLD (.top) Microsoft combosquat for update/sign-in lures | 2026-11-04 | phishunt.io (newly registered) |
| mfs-0690 | Microsoft Outlook | Session-expiry lure combosquat (AiTM session-theft theme) | 2026-11-03 | phishunt.io (newly registered) |
| mfs-0691 | Microsoft Outlook | Mailbox-quota/validation themed Outlook lookalike | 2026-11-03 | phishunt.io (newly registered) |
| mfs-0692 | Microsoft 365 support | Support-portal lookalike on .digital, same pattern as microsoftsupportcenter.digital cluster | 2026-11-03 | phishunt.io (newly registered) |
| mfs-0693 | Microsoft | Customer-care themed Microsoft combosquat | 2026-11-03 | phishunt.io (newly registered) |
| mfs-0694 | Microsoft Hotmail / Outlook.com | Doubled-letter typosquat of hotmail on .live (mimics Microsoft Live branding) | 2026-11-02 | phishunt.io (newly registered) |
| mfs-0695 | Microsoft Outlook | Truncated 'verification' combosquat (French-language lure pattern) | 2026-11-01 | phishunt.io (newly registered) |
| mfs-0696 | Microsoft OneDrive | IDN/punycode TLD abuse for a OneDrive document-share credential lure | 2026-11-01 | phishunt.io (newly registered) |
| mfs-0697 | Microsoft Office 365 | Combosquat merging 'office365' + 'online' to mimic the real sign-in host | 2026-11-01 | phishunt.io (newly registered) |
| mfs-0698 | Microsoft Outlook | Short-suffix Outlook typosquat used for webmail credential pages | 2026-11-01 | phishunt.io (newly registered) |
| mfs-0699 | Microsoft Outlook / Safe Links | Impersonates Microsoft Defender Safe Links to launder redirects to a fake sign-in | 2026-10-31 | phishunt.io (newly registered) |
| mfs-0700 | Microsoft Office 365 | Full-brand-string combosquat on cheap .top TLD | 2026-10-31 | phishunt.io (newly registered) |
| mfs-0701 | Microsoft OneDrive / MSA | Long descriptive document-share lure embedding 'msa' (Microsoft Account) sign-in theme | 2026-10-30 | phishunt.io (newly registered) |
| mfs-0702 | Microsoft OneDrive | Sync-error lure combosquat prompting re-authentication | 2026-10-30 | phishunt.io (newly registered) |
| mfs-0703 | Microsoft | Misspelled 'updates' combosquat for security-update sign-in lures | 2026-10-30 | phishunt.io (newly registered) |
| mfs-0704 | Microsoft Security / Defender | Appended-letter typosquat with security-alert sign-in lure | 2026-10-30 | phishunt.io (newly registered) |
| mfs-0705 | Microsoft Defender | Defender-branded combosquat for threat-alert credential lures | 2026-10-30 | phishunt.io (newly registered) |
| mfs-0706 | Microsoft OneDrive / Live | Shared-folder lure combosquat mixing onedrive + live branding | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0707 | Microsoft Outlook / Microsoft Account | Account-portal combosquat mimicking Microsoft account sign-in | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0708 | Microsoft Account Protection | Bulk-registered 'account protection' squat sprayed across 14+ cheap TLDs | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0709 | Microsoft Account Protection | Same bulk TLD-spray cluster; fake unusual-sign-in security alert | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0710 | Microsoft Account Protection | Bulk TLD-spray squat of account.protection.microsoft branding | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0711 | Microsoft Account Protection | Bulk TLD-spray squat on .sbs | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0712 | Microsoft Account Protection | Bulk TLD-spray squat on .monster | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0713 | Microsoft Account Protection | Bulk TLD-spray squat on .cyou | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0714 | Microsoft Account Protection | Bulk TLD-spray squat on .buzz | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0715 | Microsoft Outlook | Notification-themed Outlook combosquat for sign-in harvesting | 2026-10-29 | phishunt.io (newly registered) |
| mfs-0716 | Microsoft 365 | SkyW4lker phishing kit node abusing OAuth 2.0 device-code flow (T1528) on free dynamic-DNS host | 2026-10-27 | ANY.RUN |
| mfs-0717 | Microsoft 365 | SkyW4lker kit hosting domain; landing path matches //it[A-Za-z0-9]{32}us | 2026-10-27 | ANY.RUN |
| mfs-0718 | Microsoft 365 | SkyW4lker kit hosting domain with CAPTCHA/sandbox evasion before the M365 logon clone | 2026-10-27 | ANY.RUN |
| mfs-0719 | Microsoft 365 | SkyW4lker kit hosting domain reached via Google Sites / Smartsheet redirect chains | 2026-10-27 | ANY.RUN |
| mfs-0720 | Microsoft 365 | SkyW4lker kit hosting domain; obfuscator.io-packed JS credential capture | 2026-10-27 | ANY.RUN |
| mfs-0721 | Microsoft 365 | SkyW4lker kit node on FreeDNS dynamic-DNS subdomain | 2026-10-27 | ANY.RUN |
| mfs-0722 | Microsoft 365 | SkyW4lker kit node delivered via password-protected PDF/XLS/DOCX attachments | 2026-10-27 | ANY.RUN |
| mfs-0723 | Microsoft Outlook | Credential-harvesting fake Outlook sign-in hosted on Firebase/Google web.app free hosting (page title 'Sample Background') | 2026-11-01 | PhishDestroy |
| mfs-0724 | Microsoft Outlook | Same kit as the .web.app twin — Firebase-hosted fake Outlook login; firebaseapp.com is the paired default domain for the same Firebase project | 2026-11-01 | PhishDestroy |
| mfs-0725 | Microsoft SharePoint / OneDrive | Deep subdomain-chain impersonation ('ShareP0int' page) on an attacker-registered .cc domain, with fake passkey/auth labels to push the real domain off the visible URL bar | 2026-10-20 | PhishDestroy |
| mfs-0726 | Microsoft Account / Live | Spanish-language 'verify your account' typosquat (micros0ft with a zero) on free zya.me dynamic-DNS hosting | 2026-11-05 | phishunt.io (hourly Microsoft phishing tracker) |
| mfs-0727 | Microsoft 365 / Entra ID | SkyW4lker ('x365 Sentinel') device-code phishing landing on a Microsoft-themed subdomain chain — victim is shown a real Entra device code to enter at login.microsoft.com/device, yielding a valid session with no password or MFA bypass | 2026-11-04 | Cyber Security News / ANY.RUN research |
| mfs-0728 | Microsoft 365 / Entra ID | SkyW4lker device-code phishing — .org sibling of the same actor-controlled domain pair, serving the same landing tokens (//it[A-Za-z0-9]{32}us) | 2026-11-04 | Cyber Security News / ANY.RUN research |
| mfs-0729 | Microsoft 365 / Entra ID | Fake OpenAI Academy event RSVP page with 'Continue with Microsoft' button feeding Kali365 device-code phishing | 2026-11-05 | Push Security |
| mfs-0730 | Microsoft 365 / Entra ID | Fake SpaceX AI briefing RSVP lure chaining to Kali365 Microsoft device-code phishing | 2026-11-05 | Push Security |
| mfs-0731 | Microsoft 365 / Entra ID | Fake 'Anthropic at AWS re:Invent' event page offering Microsoft SSO that drives device-code consent | 2026-11-05 | Push Security |
| mfs-0732 | Microsoft 365 / Entra ID | Registration-stage lure host in the AI-event campaign preceding the Microsoft sign-in relay | 2026-11-05 | Push Security |
| mfs-0733 | Microsoft 365 / Entra ID | Kali365 PhaaS backend API that mints Microsoft device codes on demand for the lure pages | 2026-11-05 | Push Security |
| mfs-0734 | Microsoft Office 365 | AiTM relay host presenting the Microsoft sign-in continuation step after the device code is displayed | 2026-11-05 | Push Security |
| mfs-0735 | Microsoft 365 SSO | Fake corporate SSO portal proxying the Microsoft sign-in flow (AiTM) | 2026-11-05 | Push Security |
| mfs-0736 | Microsoft 365 SSO | Apex of the fake SSO relay domain used in the AI-event Microsoft phishing chain | 2026-11-05 | Push Security |
| mfs-0737 | Microsoft Office 365 | Office-themed AiTM sign-in confirmation page harvesting credentials and session tokens | 2026-11-05 | Push Security |
| mfs-0738 | Microsoft Office 365 | Event-registration pivot host on the officegocrqb AiTM infrastructure | 2026-11-05 | Push Security |
| mfs-0739 | Microsoft 365 SSO | Fake 'continue with SSO' step relaying to the real Microsoft login (AiTM) | 2026-11-05 | Push Security |
| mfs-0740 | Microsoft 365 | Typosquat ('offce') sign-in completion page in the device-code/AiTM chain | 2026-11-05 | Push Security |
| mfs-0741 | Microsoft 365 | Office typosquat apex hosting the fake Microsoft sign-in relay | 2026-11-05 | Push Security |
| mfs-0742 | Microsoft SharePoint / Office 365 | Subdomain-deception domain making 'office.com' appear to be the registrable name | 2026-11-05 | Push Security |
| mfs-0743 | Microsoft 365 / Entra ID | sslip.io wildcard-DNS collection endpoint exfiltrating harvested data from the lure pages | 2026-11-05 | Push Security |
| mfs-0744 | Microsoft OneDrive | Quishing — QR code embedded in a Word 'salary review' attachment leading to a fake OneDrive sign-in portal plus device-code relay | 2026-11-05 | Microsoft Threat Intelligence |
| mfs-0745 | Microsoft 365 / Outlook | SkyW4lker x365 Sentinel device-code phishing on a deeply nested Microsoft-themed hostname chain | 2026-11-04 | ANY.RUN (via Cyber Security News) |
| mfs-0746 | Microsoft 365 / Outlook | SkyW4lker device-code phishing host using a lookalike ('holdlng') corporate domain with Outlook-themed subdomain chain | 2026-11-04 | ANY.RUN (via Cyber Security News) |
| mfs-0747 | Microsoft 365 | Credential-exfiltration endpoint behind the microsoftofice.cz fake IT-department sign-in pages (two-step username/password capture) | 2026-11-04 | Flare Research (via Security Boulevard) |
| mfs-0748 | Microsoft 365 | Homoglyph typosquat of microsoftonline.com ('ti' for 'li') | 2026-11-05 | phishunt.io |
| mfs-0749 | Microsoft 365 | Character-transposition typosquat of microsoftonline ('onilne') with regional suffix | 2026-11-05 | phishunt.io |
| mfs-0750 | Microsoft 365 | Double-hyphen typosquat mimicking login.microsoftonline.com | 2026-11-05 | phishunt.io |
| mfs-0751 | Microsoft 365 | Brand-keyword squat posing as a Microsoft 365 email service sign-in | 2026-11-05 | phishunt.io |
| mfs-0752 | Microsoft Live / Hotmail | Doubled-letter typosquat of hotmail.com targeting consumer Microsoft account sign-in | 2026-11-05 | phishunt.io |
| mfs-0753 | Microsoft | Fake Microsoft CDN host used to serve sign-in/credential pages and payloads | 2026-11-05 | phishunt.io |
| mfs-0754 | Microsoft Outlook | Outlook brand squat hosting webmail sign-in impersonation | 2026-11-04 | phishunt.io |
| mfs-0755 | Microsoft Outlook | Adjective-prefixed Outlook squat typical of auto-generated phishing hosts | 2026-11-04 | phishunt.io |
| mfs-0756 | Microsoft Outlook | Fake migration/notes-to-Outlook utility used as a credential-harvest pretext | 2026-11-04 | phishunt.io |
| mfs-0757 | Microsoft Outlook | Dual-brand (Outlook+Gmail) squat offering a fake mail provider chooser before Microsoft credential capture | 2026-11-04 | phishunt.io |
| mfs-0758 | Microsoft Outlook | Fake 'Outlook center' portal on a low-reputation .biz registration | 2026-11-04 | phishunt.io |
| mfs-0759 | Microsoft 365 / Outlook | Numeric typosquat ('366' for '365') hosting an Outlook sign-in clone | 2026-11-04 | phishunt.io |
| mfs-0760 | Microsoft Outlook | Fake Outlook mail-tracking service pretext leading to sign-in capture | 2026-11-04 | phishunt.io |
| mfs-0761 | Microsoft Outlook | Generic Outlook information portal squat used for credential-phishing landing pages | 2026-11-04 | phishunt.io |
| mfs-0762 | Microsoft Outlook | 'Review your Outlook account' urgency pretext squat | 2026-11-04 | phishunt.io |
| mfs-0763 | Microsoft OneDrive | OneDrive squat ('onedriver') posing as a shared-document portal requiring Microsoft sign-in | 2026-11-04 | phishunt.io |
| mfs-0764 | Microsoft OneDrive | Fake OneDrive storage portal used for file-share credential phishing | 2026-11-04 | phishunt.io |
| mfs-0765 | Microsoft OneDrive | Appended-character OneDrive typosquat | 2026-11-04 | phishunt.io |
| mfs-0766 | Microsoft | Fake Microsoft setup/activation page prompting account sign-in | 2026-11-04 | phishunt.io |
| mfs-0767 | Microsoft | Pluralized brand squat on an infrastructure-themed TLD | 2026-11-04 | phishunt.io |
| mfs-0768 | Microsoft | Fake Microsoft update notice driving account re-authentication | 2026-11-04 | phishunt.io |
| mfs-0769 | Microsoft | Update-themed squat used for credential and tech-support style sign-in capture | 2026-11-04 | phishunt.io |
| mfs-0770 | Microsoft | Hyphenated update-themed Microsoft squat on an unusual TLD | 2026-11-04 | phishunt.io |
| mfs-0771 | Microsoft 365 | Fake Microsoft 365 plan/licensing page leading to a sign-in form | 2026-11-04 | phishunt.io |
| mfs-0772 | Microsoft 365 / Office | Fake Office download portal requiring Microsoft account authentication | 2026-11-04 | phishunt.io |
| mfs-0773 | Microsoft 365 | Pluralized Microsoft 365 typosquat | 2026-11-04 | phishunt.io |
| mfs-0774 | Microsoft | Short-suffix Microsoft brand squat used for sign-in landing pages | 2026-11-04 | phishunt.io |
| mfs-0775 | Microsoft Office 365 | Fake Office 365 store/licensing front requiring Microsoft credentials | 2026-11-04 | phishunt.io |
| mfs-0776 | Microsoft Office 365 | Fake Microsoft partner portal squat soliciting tenant admin sign-in | 2026-11-04 | phishunt.io |
| mfs-0777 | Microsoft | Fake Microsoft support-ticket portal pretext for credential harvesting | 2026-11-04 | phishunt.io |
| mfs-0778 | Microsoft Live / Hotmail | Hotmail brand-keyword squat targeting consumer Microsoft account sign-in | 2026-11-04 | phishunt.io |
| mfs-0779 | Microsoft 365 | Device-code phishing (SkyW4lker kit) behind Microsoft-themed multi-label subdomain chain on look-alike corporate domain | 2026-11-04 | ANY.RUN |
| mfs-0780 | Microsoft 365 / Copilot | Device-code phishing; digit-substitution 'microsoft0365' label inside subdomain chain | 2026-11-04 | ANY.RUN |
| mfs-0781 | Microsoft 365 | Device-code phishing with self-hosted CAPTCHA gate (/assets/private_captcha/public/widget.js) | 2026-11-04 | ANY.RUN |
| mfs-0782 | Microsoft 365 | Device-code phishing; 'reauth' lure implying session expiry | 2026-11-04 | ANY.RUN |
| mfs-0783 | Microsoft 365 / Copilot | Device-code phishing behind concatenated brand labels (outlookoffice365 + microsoftcopilots) | 2026-11-04 | ANY.RUN |
| mfs-0784 | Microsoft 365 / Copilot | Device-code phishing; fake 'cloud.microsoft' suffix rendered as subdomain labels | 2026-11-04 | ANY.RUN |
| mfs-0785 | Microsoft 365 / Copilot | Device-code phishing; fake cloud.microsoft chain on typosquatted 'constructlon' (l-for-i) domain | 2026-11-04 | ANY.RUN |
| mfs-0786 | Microsoft 365 | Device-code phishing with fake OAuth/statement document lure | 2026-11-04 | ANY.RUN |
| mfs-0787 | Microsoft 365 / OneDrive | Device-code phishing; shared-document lure, 'common' label mimicking the Entra /common tenant path | 2026-11-04 | ANY.RUN |
| mfs-0788 | Microsoft 365 / OneDrive | Device-code phishing, shared-document lure | 2026-11-04 | ANY.RUN |
| mfs-0789 | Microsoft 365 / OneDrive | Device-code phishing; 'common0' rotation of the same kit template | 2026-11-04 | ANY.RUN |
| mfs-0790 | Microsoft 365 / OneDrive | Device-code phishing on typosquatted 'northem' (rn-for-m) domain | 2026-11-04 | ANY.RUN |
| mfs-0791 | Microsoft 365 / OneDrive | Device-code phishing; concatenated 'outlookonedrive' label variant | 2026-11-04 | ANY.RUN |
| mfs-0792 | Microsoft 365 / OneDrive | Device-code phishing; year-stamped 'auth2026' label on typosquatted 'rooflng' domain | 2026-11-04 | ANY.RUN |
| mfs-0793 | Microsoft 365 / Copilot | Device-code phishing; 'commm' padding label to evade exact-match blocklists | 2026-11-04 | ANY.RUN |
| mfs-0794 | Microsoft 365 / Copilot | Device-code phishing; 'copilos26' misspelled-Copilot label | 2026-11-04 | ANY.RUN |
| mfs-0795 | Microsoft 365 / Copilot | Device-code phishing, shared-document lure | 2026-11-04 | ANY.RUN |
| mfs-0796 | Microsoft 365 / SharePoint | Device-code phishing; shared-document portal lure | 2026-11-04 | ANY.RUN |
| mfs-0797 | Microsoft 365 | Device-code phishing behind eFax/voicemail document lure | 2026-11-04 | ANY.RUN |
| mfs-0798 | Microsoft 365 | Device-code phishing; eFax lure, 'outlook2026common' concatenation | 2026-11-04 | ANY.RUN |
| mfs-0799 | Microsoft 365 | Device-code phishing; payment-app lure on same host domain as the eFax variant | 2026-11-04 | ANY.RUN |
| mfs-0800 | Microsoft 365 | Device-code phishing; fake Korean corporate domain ('-co-kr' faking a ccTLD) | 2026-11-04 | ANY.RUN |
| mfs-0801 | Microsoft 365 | Device-code phishing; PDF shared-document lure | 2026-11-04 | ANY.RUN |
| mfs-0802 | Microsoft 365 | Device-code phishing; impersonates the KONE brand as the host domain | 2026-11-04 | ANY.RUN |
| mfs-0803 | Microsoft 365 | Device-code phishing; eFax + shared-docs lure | 2026-11-04 | ANY.RUN |
| mfs-0804 | Microsoft 365 | Device-code phishing; eFax + shared-docs lure | 2026-11-04 | ANY.RUN |
| mfs-0805 | Microsoft 365 | Device-code phishing; Kyocera-ECOSYS scanner-to-email lure chained to M365 sign-in | 2026-11-04 | ANY.RUN |
| mfs-0806 | Microsoft 365 | Device-code phishing; 'lntactpr' (l-for-I) typosquat with full brand chain | 2026-11-04 | ANY.RUN |
| mfs-0807 | Microsoft 365 | Device-code phishing; 'cloud-outlook' + fake microsoft label on transposed 'naregruop' domain | 2026-11-04 | ANY.RUN |
| mfs-0808 | Microsoft 365 | SkyW4lker host/apex domain serving Microsoft-themed device-code phishing subdomains | 2026-11-04 | ANY.RUN |
| mfs-0809 | Microsoft 365 | Device-code phishing behind m365cloud/login brand chain | 2026-11-04 | ANY.RUN |
| mfs-0810 | Microsoft 365 | SkyW4lker apex domain hosting M365 device-code phishing subdomains | 2026-11-04 | ANY.RUN |
| mfs-0811 | Microsoft 365 / Entra ID | Device-code phishing; entire Entra OAuth2 URL path rendered as DNS labels (microsoftonline.common.oauth2.client) | 2026-11-04 | ANY.RUN |
| mfs-0812 | Microsoft 365 / Copilot | Device-code phishing; re-authentication lure | 2026-11-04 | ANY.RUN |
| mfs-0813 | Microsoft 365 / Copilot | Device-code phishing; re-authentication lure on 'halnc' typosquat | 2026-11-04 | ANY.RUN |
| mfs-0814 | Microsoft 365 / Copilot | Device-code phishing; 'auth02' label mimicking Microsoft auth endpoints | 2026-11-04 | ANY.RUN |
| mfs-0815 | Microsoft 365 / Copilot | Device-code phishing; concatenated brand labels on 'vigilantlnc' (l-for-i) typosquat | 2026-11-04 | ANY.RUN |
| mfs-0816 | Microsoft 365 | Device-code phishing behind a billing-statement lure | 2026-11-04 | ANY.RUN |
| mfs-0817 | Microsoft 365 | SkyW4lker apex domain hosting M365 device-code phishing subdomains | 2026-11-04 | ANY.RUN |
| mfs-0818 | Microsoft 365 | Device-code phishing; payment/statement lure, 'office365microsoft' concatenation | 2026-11-04 | ANY.RUN |
| mfs-0819 | Microsoft 365 | Device-code phishing; approved-payment lure funnelling to M365 sign-in | 2026-11-04 | ANY.RUN |
| mfs-0820 | Microsoft 365 | Device-code phishing; payment-authorization lure | 2026-11-04 | ANY.RUN |
| mfs-0821 | Microsoft 365 / Copilot | Device-code phishing; payroll-document lure ('payrol2026') | 2026-11-04 | ANY.RUN |
| mfs-0822 | Microsoft 365 | Device-code phishing on free dynamic-DNS (FreeDNS mooo.com); leetspeak '0ff365' | 2026-11-04 | ANY.RUN |
| mfs-0823 | Microsoft 365 | Device-code phishing on free dynamic-DNS host | 2026-11-04 | ANY.RUN |
| mfs-0824 | Microsoft 365 | Device-code phishing; zero-for-o leetspeak admin-portal lure on free dyn-DNS | 2026-11-04 | ANY.RUN |
| mfs-0825 | Microsoft 365 | Device-code phishing; 'office0365login' leetspeak label on free dyn-DNS | 2026-11-04 | ANY.RUN |
| mfs-0826 | Microsoft 365 | Device-code phishing; 'off365' typosquat on cheap .club TLD | 2026-11-04 | ANY.RUN |
| mfs-0827 | Microsoft 365 | Device-code phishing on FreeDNS; sibling of the known flow505.mooo.com host | 2026-11-04 | ANY.RUN |
| mfs-0828 | Microsoft 365 | Device-code phishing on FreeDNS dynamic-DNS host | 2026-11-04 | ANY.RUN |
| mfs-0829 | Microsoft 365 | Device-code phishing on free dynamic-DNS host | 2026-11-04 | ANY.RUN |
| mfs-0830 | Microsoft 365 | Device-code phishing redirector on free dynamic-DNS host | 2026-11-04 | ANY.RUN |
| mfs-0831 | Microsoft 365 | Device-code phishing on free dynamic-DNS host | 2026-11-04 | ANY.RUN |
| mfs-0832 | Microsoft 365 | Device-code phishing on free dynamic-DNS host impersonating a company name | 2026-11-04 | ANY.RUN |
| mfs-0833 | Microsoft 365 | Device-code phishing; generic 'loading documents' interstitial before M365 sign-in | 2026-11-04 | ANY.RUN |
| mfs-0834 | Microsoft 365 | SkyW4lker backend/auth infrastructure domain for device-code flow | 2026-11-04 | ANY.RUN |
| mfs-0835 | Microsoft 365 | AiTM reverse proxy (VoidProxy) behind fake corporate-event registration lure | 2026-11-05 | Push Security |
| mfs-0836 | Microsoft 365 / Entra ID | VoidProxy AiTM Microsoft sign-in page harvesting credentials, MFA codes and session cookies | 2026-11-05 | Push Security |
| mfs-0837 | Microsoft 365 | Kali365 device-code phishing backend (/api/generate) behind a fake Zoom/shift-portal lure | 2026-11-05 | Push Security |
| mfs-0838 | Microsoft 365 | MadApe phishing kit host serving a fake Microsoft sign-in page from PDF-attachment lures | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0839 | Microsoft Teams | MadApe kit; Microsoft Teams voicemail-notification lure leading to device-code sign-in | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0840 | Microsoft SharePoint | MadApe kit; fake SharePoint document-share page funnelling to Microsoft device-code sign-in | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0841 | Microsoft OneDrive | MadApe kit; OneDrive-themed file-share lure to Microsoft device-code sign-in | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0842 | Microsoft 365 | MadApe redirect target presenting a fake 'secure login' step before Microsoft device-code entry | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0843 | Microsoft 365 | MadApe operator panel / kit control domain for Microsoft device-code campaigns | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0844 | Microsoft 365 | MadApe operator panel domain (earliest sighting 2026-08-19) | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0845 | Microsoft 365 | MadApe operator panel domain | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0846 | Microsoft 365 | MadApe operator panel domain | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0847 | Microsoft 365 | MadApe operator panel domain | 2026-11-03 | Aegis AI (on Group-IB research) |
| mfs-0848 | Microsoft | Fake 'Windows Update / Microsoft account' sign-in landing page on attacker-registered lookalike domain | 2026-11-08 | phishunt.io |
| mfs-0849 | Microsoft 365 | PhantomDOM browser-in-the-middle: entry host issues campaign JWT then hands off to DOM-mirroring auth subdomain | 2026-11-05 | ZeroBEC |
| mfs-0850 | Microsoft 365 | Browser-in-the-middle DOM mirroring of login.microsoftonline.com behind Cloudflare Turnstile | 2026-11-05 | ZeroBEC |
| mfs-0851 | Microsoft 365 | Rotating BitM authentication subdomain reconstructing the M365 sign-in DOM locally | 2026-11-05 | ZeroBEC |
| mfs-0852 | Microsoft 365 | Attacker-controlled BitM authentication host hijacking M365 sessions | 2026-11-05 | ZeroBEC |
| mfs-0853 | Microsoft 365 | Attacker-controlled BitM authentication host hijacking M365 sessions | 2026-11-05 | ZeroBEC |
| mfs-0854 | Microsoft 365 | Post-session exit host redirecting victims to a decoy DocuSign page after token theft | 2026-11-05 | ZeroBEC |
| mfs-0855 | Microsoft 365 | Parent phishing infrastructure for the PhantomDOM BitM M365 kit | 2026-11-05 | ZeroBEC |
| mfs-0856 | Microsoft 365 | Click-tracking redirector hop in the PhantomDOM M365 BitM chain (likely compromised site) | 2026-11-05 | ZeroBEC |
| mfs-0857 | Microsoft 365 | First-stage anti-bot/fingerprinting gate in front of the PhantomDOM M365 sign-in page | 2026-11-05 | ZeroBEC |
| mfs-0858 | Microsoft 365 | Typosquat of microsoftonline.com ('microsoftsonline') on cheap .sbs TLD | 2026-11-09 | phishunt.io |
| mfs-0859 | Microsoft 365 | Typosquat of microsoftonline.com registered as part of a multi-TLD cluster | 2026-11-09 | phishunt.io |
| mfs-0860 | Microsoft 365 | Typosquat of microsoftonline.com on abuse-heavy .cfd TLD | 2026-11-09 | phishunt.io |
| mfs-0861 | Microsoft 365 | Brand-concatenation squat ('m365online-microsoft') posing as the M365 portal | 2026-11-09 | phishunt.io |
| mfs-0862 | Microsoft | Digit-appended typosquat of microsoft.com used for account sign-in lures | 2026-11-09 | phishunt.io |
| mfs-0863 | Microsoft | Brand-extension squat impersonating Microsoft desktop/account services | 2026-11-09 | phishunt.io |
| mfs-0864 | Microsoft Hotmail/Outlook | Hotmail-suffixed lookalike domain mimicking a mailbox-owner address for credential capture | 2026-11-09 | phishunt.io |
| mfs-0865 | Microsoft | Geo-themed brand squat ('Microsoft Indonesia') hosting regional sign-in lures | 2026-11-09 | phishunt.io |
| mfs-0866 | Microsoft | Edge-branded squat on .homes TLD used for update/sign-in prompts | 2026-11-09 | phishunt.io |
| mfs-0867 | Microsoft Outlook | Homoglyph typosquat substituting 'rn' for 'm' in 'microsoft' | 2026-11-08 | phishunt.io |
| mfs-0868 | Microsoft Outlook | Character-omission typosquat ('microsft') for Outlook webmail credential theft | 2026-11-08 | phishunt.io |
| mfs-0869 | Microsoft 365 | Explicit 'microsoft365-login' credential-harvest domain on .online TLD | 2026-11-08 | phishunt.io |
| mfs-0870 | Microsoft 365 | Fake Microsoft 365 authentication endpoint domain | 2026-11-08 | phishunt.io |
| mfs-0871 | Microsoft Outlook | Security-themed Outlook squat ('shield') for mailbox-protection sign-in lures | 2026-11-08 | phishunt.io |
| mfs-0872 | Microsoft Outlook | Security-themed Outlook squat on .site TLD, sibling of outlookshield.com | 2026-11-08 | phishunt.io |
| mfs-0873 | Microsoft Outlook | Outlook brand squat on .app TLD presenting a webmail sign-in form | 2026-11-08 | phishunt.io |
| mfs-0874 | Microsoft OneDrive | OneDrive 'open document' lure domain fronting a Microsoft sign-in prompt | 2026-11-08 | phishunt.io |
| mfs-0875 | Microsoft OneDrive | Fake OneDrive support/help portal harvesting Microsoft account credentials | 2026-11-08 | phishunt.io |
| mfs-0876 | Microsoft Hotmail | Exact brand name on an unrelated vanity TLD (.ceo) for webmail credential capture | 2026-11-08 | phishunt.io |
| mfs-0877 | Microsoft 365 | IDN homoglyph attack — punycode domain rendering as a Unicode 'microsoftonline' lookalike | 2026-11-07 | phishunt.io |
| mfs-0878 | Microsoft 365 | Digit-for-letter typosquat of microsoftonline.com (1 for i) | 2026-11-07 | phishunt.io |
| mfs-0879 | Microsoft | Digit-substitution typosquat ('micros0ft') on a fake auth endpoint | 2026-11-07 | phishunt.io |
| mfs-0880 | Microsoft 365 | Generic 'microsoft-login' credential-harvest domain on .online TLD | 2026-11-07 | phishunt.io |
| mfs-0881 | Microsoft 365 / Defender | Defender-themed security-alert lure domain leading to an Office 365 sign-in page | 2026-11-07 | phishunt.io |
| mfs-0882 | Microsoft | Fake Microsoft support portal on .fun TLD used for account-verification sign-in lures | 2026-11-07 | phishunt.io |
| mfs-0883 | Microsoft Live/Hotmail | Possessive-prefix squat ('your-hotmail-live') impersonating Microsoft Live sign-in | 2026-11-07 | phishunt.io |
| mfs-0884 | Microsoft OneDrive/Azure | Fake Microsoft storage/quota warning domain on .shop TLD | 2026-11-06 | phishunt.io |
| mfs-0885 | Microsoft | Security-themed brand squat ('shield-microsoft') for account-protection sign-in lures | 2026-11-06 | phishunt.io |
| mfs-0886 | Microsoft Outlook | Pluralized Outlook squat on .page TLD serving a webmail sign-in form | 2026-11-06 | phishunt.io |
| mfs-0887 | Microsoft Outlook | Targeted squat embedding a victim-organization token after 'outlook-' for a tailored sign-in lure | 2026-11-06 | phishunt.io |
| mfs-0888 | Microsoft Hotmail | Character-padded Hotmail typosquat ('hotmaililil') on .shop TLD | 2026-11-06 | phishunt.io |

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

### mfs-0621 — Microsoft 365

```text
https://miicro67soft.vercel.app/
```

- **Domain:** `miicro67soft.vercel.app`
- **Technique:** Typosquat homoglyph domain ('miicro67soft') hosting a cloned Microsoft sign-in page on free Vercel hosting
- **Detection:** Alert on *.vercel.app referrers in proxy logs where the page title/favicon matches Microsoft; regex hostnames with doubled 'ii'/digits inside 'microsoft'
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9553417
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0622 — Microsoft 365

```text
https://oosoftlms.weebly.com/
```

- **Domain:** `oosoftlms.weebly.com`
- **Technique:** Free Weebly site-builder page serving a fake Microsoft/Office credential form
- **Detection:** Block or alert on *.weebly.com POSTs from corporate endpoints; no business reason for Weebly auth forms
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9553175
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0623 — Microsoft 365

```text
https://knkddkmlmeaedd.weebly.com/
```

- **Domain:** `knkddkmlmeaedd.weebly.com`
- **Technique:** Random-string Weebly subdomain hosting a Microsoft sign-in clone (same kit cluster as oosoftlms)
- **Detection:** Hunt *.weebly.com hostnames with high-entropy/consonant-only labels in DNS and web proxy logs
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9553174
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0624 — Microsoft 365

```text
https://security-server-website--danlelbacker.replit.app/
```

- **Domain:** `security-server-website--danlelbacker.replit.app`
- **Technique:** Replit-hosted 'security server' lure redirecting to a fake Microsoft login (note 'danlel' = Daniel typosquat)
- **Detection:** Alert on *.replit.app hostnames containing 'security', 'server', 'login' or 'verify'; Replit app subdomains are a recurring Microsoft phish host
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9552908
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0625 — Microsoft 365

```text
https://admin-suport-update-com.weebly.com/
```

- **Domain:** `admin-suport-update-com.weebly.com`
- **Technique:** Misspelled 'admin-suport-update' Weebly page impersonating a Microsoft 365 admin/account update portal
- **Detection:** Regex for misspellings 'suport', 'verifiy', 'acount' in hostnames/paths plus Microsoft brand strings in page body
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9552904
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0626 — Microsoft

```text
https://help.microsofth.com
```

- **Domain:** `help.microsofth.com`
- **Technique:** Typosquat of microsoft.com with an appended 'h' (microsofth[.]com), wildcard subdomains mimicking real Microsoft service hostnames
- **Detection:** Hunt DNS for *.microsofth.com; broadly, alert on any registrable domain matching ^microsoft.$ or microsoft[a-z]\.(com|net) that is not Microsoft-owned
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0627 — Microsoft Entra ID

```text
https://auth.microsofth.com
```

- **Domain:** `auth.microsofth.com`
- **Technique:** Typosquat subdomain posing as a Microsoft authentication endpoint (auth.microsofth[.]com)
- **Detection:** Treat any 'auth.'/'login.'/'sso.' label on a non-Microsoft-owned microsoft* domain as high-confidence phishing; add to DNS sinkhole
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0628 — Microsoft 365

```text
https://apps.microsofth.com
```

- **Domain:** `apps.microsofth.com`
- **Technique:** Typosquat subdomain mimicking the Microsoft 365 app launcher (apps.microsoft.com lookalike)
- **Detection:** Compare resolved hostname against an allowlist of genuine Microsoft apex domains (microsoft.com, microsoftonline.com, cloud.microsoft) before permitting auth flows
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0629 — Microsoft Azure

```text
https://azure.microsofth.com
```

- **Domain:** `azure.microsofth.com`
- **Technique:** Typosquat subdomain impersonating the Azure portal on microsofth[.]com
- **Detection:** Alert when a page referencing 'Azure Portal' or 'Sign in to Azure' is served from a domain other than azure.com / microsoftonline.com
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0630 — Microsoft 365

```text
https://cloud.microsofth.com
```

- **Domain:** `cloud.microsofth.com`
- **Technique:** Typosquat subdomain imitating Microsoft's cloud.microsoft first-party domain
- **Detection:** Flag lookalikes of the newer cloud.microsoft brand domain; users are not yet trained to recognise it
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0631 — Microsoft

```text
https://com.microsofth.com
```

- **Domain:** `com.microsofth.com`
- **Technique:** Deceptive 'com.' label so the hostname reads like microsoft.com in truncated mobile address bars
- **Detection:** Hunt hostnames where the leftmost label is a TLD string ('com.', 'net.', 'org.') — a classic mobile URL-truncation trick
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0632 — Microsoft

```text
https://data.microsofth.com
```

- **Domain:** `data.microsofth.com`
- **Technique:** Typosquat subdomain on the microsofth[.]com phishing wildcard infrastructure
- **Detection:** Pivot on the microsofth.com registration (registrar, NS, TLS cert SANs) to pre-emptively block all siblings
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0633 — Microsoft

```text
https://dotnet.microsofth.com
```

- **Domain:** `dotnet.microsofth.com`
- **Technique:** Typosquat subdomain impersonating dotnet.microsoft.com developer portal
- **Detection:** Use CT-log monitoring for certificates with SANs matching *.microsoft?.com patterns
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0634 — Microsoft Edge

```text
https://edge.microsofth.com
```

- **Domain:** `edge.microsofth.com`
- **Technique:** Typosquat subdomain posing as an Edge browser/update page — likely update-lure to credential or payload
- **Detection:** Alert on 'browser update required' pages served from non-Microsoft domains; Edge never updates via a web form
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0635 — Microsoft Power Automate

```text
https://flow.microsofth.com
```

- **Domain:** `flow.microsofth.com`
- **Technique:** Typosquat subdomain impersonating flow.microsoft.com (Power Automate) sign-in
- **Detection:** Low-traffic Microsoft service brands (Flow, Power Automate, Dataverse) on unknown domains are strong phishing signals
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0636 — Microsoft 365

```text
https://security-server-page--michaelfrank112.replit.app/
```

- **Domain:** `security-server-page--michaelfrank112.replit.app`
- **Technique:** Replit-hosted fake Microsoft security-alert sign-in page; same kit/naming scheme as the 'security-server-*' cluster
- **Detection:** Regex proxy logs for /security-server-[a-z-]*--[a-z0-9]+\.replit\.app/ and block the whole cluster
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9552435
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0637 — Microsoft 365

```text
https://kalgaaaaa.webflow.io/
```

- **Domain:** `kalgaaaaa.webflow.io`
- **Technique:** Webflow-hosted landing page cloning the Microsoft sign-in experience
- **Detection:** Alert on *.webflow.io pages whose DOM contains 'login.microsoftonline.com', 'urlMsaSignUp' or the Microsoft logo SVG
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9552421
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0638 — Microsoft OneDrive

```text
https://biesse.en-onedrive.com
```

- **Domain:** `biesse.en-onedrive.com`
- **Technique:** Targeted typosquat (en-onedrive[.]com) with a victim-company subdomain serving a fake OneDrive document-share sign-in
- **Detection:** Hunt for your own company name used as a subdomain label on third-party domains — a hallmark of targeted OneDrive/SharePoint lures
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0639 — Microsoft Outlook

```text
https://aiapp2.outlook1.cc
```

- **Domain:** `aiapp2.outlook1.cc`
- **Technique:** Outlook typosquat on a cheap .cc TLD hosting a webmail credential form
- **Detection:** Block brand+digit permutations (outlook1, outlook365, office1) across cheap TLDs (.cc, .cfd, .sbs, .click)
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0640 — Microsoft 365

```text
https://sdc.bcn.mybluehost.me/
```

- **Domain:** `sdc.bcn.mybluehost.me`
- **Technique:** Compromised Bluehost staging/temp hostname (*.mybluehost.me) repurposed to host a Microsoft credential-harvest page
- **Detection:** Alert on *.mybluehost.me and other hoster staging domains (*.temp.domains, *.wpengine.com) appearing in email links
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9551744
- **Status:** active
- **First seen:** 2026-10-28

### mfs-0641 — Microsoft 365

```text
http://sdc.bcn.mybluehost.me/
```

- **Domain:** `sdc.bcn.mybluehost.me`
- **Technique:** Plain-HTTP variant of the same compromised Bluehost staging host serving the Microsoft sign-in clone
- **Detection:** Any cleartext HTTP page collecting credentials is phishing by definition — block HTTP POSTs with password fields at the proxy
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9551745
- **Status:** active
- **First seen:** 2026-10-28

### mfs-0642 — Microsoft 365

```text
https://global-fuchsia-9par6vcz-dp5x4caf1rmk.edgeone.dev/
```

- **Domain:** `global-fuchsia-9par6vcz-dp5x4caf1rmk.edgeone.dev`
- **Technique:** Tencent EdgeOne Pages (*.edgeone.dev) free edge hosting with a randomised subdomain fronting a fake Microsoft login
- **Detection:** Add *.edgeone.dev to your newly-abused-hosting watchlist; alert on high-entropy multi-segment labels on edge/CDN dev domains
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9551571
- **Status:** active
- **First seen:** 2026-10-28

### mfs-0643 — Microsoft 365

```text
https://microfis-password-recovery.wasmer.app/
```

- **Domain:** `microfis-password-recovery.wasmer.app`
- **Technique:** Wasmer Edge hosting a 'Microfis' (Microsoft typosquat) password-recovery / password-reset credential lure
- **Detection:** Hunt *.wasmer.app plus hostnames containing 'password-recovery', 'password-reset', 'mfa-reset' not on your IdP domain
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9551418
- **Status:** active
- **First seen:** 2026-10-28

### mfs-0644 — Microsoft 365

```text
https://doc-portail-groupegouletsports.vercel.app/
```

- **Domain:** `doc-portail-groupegouletsports.vercel.app`
- **Technique:** French-language 'document portal' lure impersonating a company's Microsoft 365 document share, hosted on Vercel
- **Detection:** Alert on Vercel/Netlify subdomains containing a customer or partner company name plus 'portail'/'portal'/'doc'
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9549571
- **Status:** active
- **First seen:** 2026-10-24

### mfs-0645 — Microsoft 365

```text
https://plusone.google.com/url?q=https://google.com/goto?url=CAESTwHrOzAVYLp8p1XZJG3imToMgFa2CMsN28j3zx0_-j3EdY33VVKjQUcnZf9qOdQe3ATzWIGnW_C5okF3IO9Iefgr6ax7lDYxIGREg-umcSY
```

- **Domain:** `plusone.google.com`
- **Technique:** Chained Google open-redirect (plusone.google.com/url?q= → google.com/goto?url=) delivering victims to a fake Microsoft sign-in page
- **Detection:** Unwrap and inspect nested redirector parameters (?q=, ?url=, &continue=) at the gateway; treat google.com/goto and plusone.google.com/url links in inbound mail as hostile
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9549168
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0646 — Microsoft 365

```text
https://shohag.shop/
```

- **Domain:** `shohag.shop`
- **Technique:** Compromised/abused .shop e-commerce domain repurposed as a Microsoft credential-harvest landing page
- **Detection:** Flag newly-registered or low-reputation .shop/.store domains that serve pages containing Microsoft branding
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9549167
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0647 — Microsoft 365

```text
https://fls-a2a307fb-f2fd-4664-8c1e-e855892944cf.laravel.cloud/eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJjYW1wYWlnbklkIjoiNWFiYmY2MjQtOTc3ZC0xMWVmLWJhZWItMjk2ZWI2NWZmZDY2IiwiZW1haW-gg.html
```

- **Domain:** `fls-a2a307fb-f2fd-4664-8c1e-e855892944cf.laravel.cloud`
- **Technique:** Laravel Cloud hosting with a base64/JWT-encoded path embedding campaignId and victim email — per-recipient pre-filled Microsoft phish
- **Detection:** Decode base64 URL path segments at the gateway and alert on decoded 'campaignId'/'email' keys; watch *.laravel.cloud
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9549165
- **Status:** active
- **First seen:** 2026-10-23

### mfs-0648 — Microsoft 365

```text
https://achermanrmalerch.click
```

- **Domain:** `achermanrmalerch.click`
- **Technique:** Disposable .click domain with a random-looking label serving a Microsoft sign-in clone
- **Detection:** Block .click/.cfd/.sbs/.lat TLDs outright or gate them behind newly-registered-domain blocking (<30 days)
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9547984
- **Status:** active
- **First seen:** 2026-10-21

### mfs-0649 — Microsoft 365

```text
https://fairsealines.com/scope/%7B%7BrandomVIII%7D%7D
```

- **Domain:** `fairsealines.com`
- **Technique:** Compromised legitimate site hosting a phish kit whose unrendered {{randomVIII}} template token leaked into the live URL
- **Detection:** Grep web/mail logs for literal template placeholders — %7B%7B, {{, <%=, ${ — inside URLs; a dead giveaway for phish-kit misconfiguration
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9547853
- **Status:** active
- **First seen:** 2026-10-21

### mfs-0650 — Microsoft 365

```text
https://leanl-rosy.vercel.app/
```

- **Domain:** `leanl-rosy.vercel.app`
- **Technique:** Vercel auto-generated '<word>-<colour>' project subdomain hosting a Microsoft credential page
- **Detection:** Vercel's default adjective/colour naming ('-rosy', '-silk', '-coral', '-ashy', '-phi') on *.vercel.app is a reliable heuristic for this actor cluster
- **Source:** PhishTank — http://www.phishtank.com/phish_detail.php?phish_id=9547604
- **Status:** active
- **First seen:** 2026-10-21

### mfs-0652 — Microsoft Office 365

```text
https://arasyaplastic.com/pronto_office/solid.html
```

- **Domain:** `arasyaplastic.com`
- **Technique:** Compromised corporate website hosting a static HTML Office 365 credential-harvest page in an uploaded '/pronto_office/' kit directory
- **Detection:** Hunt proxy logs for standalone .html files under directories containing 'office','owa','o365' on unrelated business domains
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0653 — Microsoft SharePoint

```text
http://www.sharepoint-notification.vercel.app/
```

- **Domain:** `www.sharepoint-notification.vercel.app`
- **Technique:** SharePoint 'document notification' lure on Vercel, served over plain HTTP, leading to a Microsoft sign-in prompt
- **Detection:** Alert on hostnames combining a Microsoft product name with 'notification','alert','share' on free PaaS (vercel.app, netlify.app, pages.dev, workers.dev)
- **Source:** OpenPhish — https://openphish.com/feed.txt
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0654 — Microsoft 365

```text
https://pay.myoffice365.ninja
```

- **Domain:** `pay.myoffice365.ninja`
- **Technique:** Fake 'My Office 365' online payment/billing form harvesting card + account data (GoDaddy-registered, AWS-hosted)
- **Detection:** Alert on newly-registered .ninja/.site/.online domains containing 'office365' or 'myoffice' in proxy logs; block DNS to 100.49.110.141
- **Source:** PhishDestroy (DestroyList) — https://phishdestroy.io/domain/pay.myoffice365.ninja
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0655 — Microsoft Office 365

```text
https://office365login-1f9d1.web.app/
```

- **Domain:** `office365login-1f9d1.web.app`
- **Technique:** Firebase *.web.app free-hosting credential page with 'Redirecting.....' cloaking that bounces non-targets to Google Search
- **Detection:** Hunt HTTP requests to *.web.app / *.firebaseapp.com hosts whose subdomain matches /office|o365|microsoft|login/ plus a trailing 5-hex Firebase project suffix
- **Source:** PhishDestroy (DestroyList) — https://phishdestroy.io/domain/office365login-1f9d1.web.app/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0656 — Microsoft Office 365

```text
https://office365-ff2ac.firebaseapp.com/
```

- **Domain:** `office365-ff2ac.firebaseapp.com`
- **Technique:** Firebase-hosted Office 365 lookalike using redirect-to-Google cloaking to evade sandboxes
- **Detection:** Same Firebase project-ID pattern as office365login-1f9d1.web.app — pivot on Google NS + 'office365-' prefix; 15/92 VT engines
- **Source:** PhishDestroy (DestroyList) — https://phishdestroy.io/domain/office365-ff2ac.firebaseapp.com
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0657 — Microsoft Outlook / Exchange OWA

```text
https://owa-mail-auth.firebaseapp.com/
```

- **Domain:** `owa-mail-auth.firebaseapp.com`
- **Technique:** Fake Outlook Web Access authentication page (page title 'Outlookionos-webmail') on Firebase hosting
- **Detection:** Flag any *.firebaseapp.com host containing 'owa', 'mail-auth' or 'webmail'; 21/92 VT, urlscan score 93
- **Source:** PhishDestroy (DestroyList) — https://phishdestroy.io/domain/owa-mail-auth.firebaseapp.com/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0658 — Microsoft Office / Microsoft 365

```text
https://officeadmin2026.weebly.com/
```

- **Domain:** `officeadmin2026.weebly.com`
- **Technique:** Weebly free-site 'Microsoft Office Account' form abusing a fake 'Encourage Multi-Factor Authenticator (EMFA)' pretext to collect name, school email, password and phone
- **Detection:** Education-sector lure — alert on *.weebly.com referers in M365 sign-in logs and on form posts to weebly.com from mail links; hunt 'EMFA' string in reported emails
- **Source:** PhishDestroy (DestroyList) — https://phishdestroy.io/domain/officeadmin2026.weebly.com/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0659 — Microsoft

```text
https://microsoftoniine.my/
```

- **Domain:** `microsoftoniine.my`
- **Technique:** Typosquat (microsoftonline → microsoftoniine, l→i homoglyph) on .my ccTLD; registered 2026-10-10, parked ~9.5h after detection
- **Detection:** Run homoglyph/edit-distance-1 generation against 'microsoftonline' across new-gTLD feeds; cert SAN reuse with cpcontacts.mycloudforward.com indicates shared kit infrastructure
- **Source:** PhishDestroy / Spamhaus DBL / SEAL — https://phishdestroy.io/domain/microsoftoniine.my/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0660 — Microsoft Outlook

```text
https://outlook.accountantsclaim.com/
```

- **Domain:** `outlook.accountantsclaim.com`
- **Technique:** Subdomain spoof ('outlook.' prefix on an unrelated apex) serving a credential page behind a Cloudflare access challenge
- **Detection:** Alert on any non-Microsoft apex serving an 'outlook.'/'login.'/'owa.' subdomain over Cloudflare; CNAME-pivot on accountantsclaim.com
- **Source:** PhishDestroy (DestroyList) — https://phishdestroy.io/domain/outlook.accountantsclaim.com/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0661 — Microsoft 365 / Azure AD (Entra ID)

```text
https://login-microsoftonline.pl/
```

- **Domain:** `login-microsoftonline.pl`
- **Technique:** ccTLD lookalike of login.microsoftonline.com (hyphen-swap for the dot); nazwa.pl registrar, hosted 85.128.128.104 Krakow — still confirmed live 2026-11-01
- **Detection:** Block the hyphen-variant family 'login-microsoftonline.*'; any DNS resolution to 85.128.128.104 from user subnets is high-fidelity
- **Source:** PhishDestroy / Spamhaus DBL / AlienVault OTX — https://phishdestroy.io/domain/login-microsoftonline.pl/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0662 — Microsoft Office 365

```text
https://www.microsoft-office365.site/
```

- **Domain:** `www.microsoft-office365.site`
- **Technique:** Spanish-language fake 'Iniciar sesion' Microsoft login on Vercel; urlscan exposed JS globals 'discordWebhook' and 'adminPassword' — credentials exfiltrated via Discord webhook. Still active 2026-11-01
- **Detection:** Hunt outbound POSTs to discord.com/api/webhooks from browser sessions following a Microsoft-themed page load; block *.site domains matching 'microsoft-office'
- **Source:** PhishDestroy / Google Safe Browsing — https://phishdestroy.io/domain/microsoft-office365.site/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0663 — Microsoft

```text
http://micronosoft.com/
```

- **Domain:** `micronosoft.com`
- **Technique:** Typosquat (micronosoft) hosting a Microsoft-service subdomain farm — login.micronosoft.com and teams.micronosoft.com — with HTTP 302 redirect chain; last active 2026-11-01
- **Detection:** Enumerate and sinkhole all subdomains of micronosoft.com, not just the apex; urlscan phishing score 100, 5/92 VT
- **Source:** PhishDestroy / MetaMask / SEAL — https://phishdestroy.io/domain/micronosoft.com/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0664 — Microsoft Outlook

```text
https://emergingoutlookreport.com/
```

- **Domain:** `emergingoutlookreport.com`
- **Technique:** Impersonation-class Outlook phishing on Cloudflare CDN (London); NameCheap registration 2026-06-23, TLS valid to 2027-01-17
- **Detection:** Alert on 'outlook'-containing apex domains aged <6 months behind Cloudflare; 16/92 VT, 3 OTX community references
- **Source:** PhishDestroy / AlienVault OTX — https://phishdestroy.io/domain/emergingoutlookreport.com/
- **Status:** active
- **First seen:** 2026-10-26

### mfs-0665 — Microsoft 365

```text
https://microsoftt7.vercel.app
```

- **Domain:** `microsoftt7.vercel.app`
- **Technique:** Vercel-hosted static credential harvester — generic "Welcome Back!" page with Microsoft-branded sign-in form posting creds to an attacker endpoint
- **Detection:** Alert on HTTP POST/XHR to *.vercel.app from mail-link clicks where the referring page title is 'Welcome Back!' and no prior Microsoft tenant context exists; block newly-registered vercel.app subdomains matching /microsoft/i
- **Source:** phishunt.io (also in OpenPhish public feed) — https://phishunt.io/suspicious/microsoft/b13b7335-2916-4808-9d2f-49673ef1d81f/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0666 — Microsoft Teams / SharePoint Online

```text
https://teams.microsoftonline-sharepoint.online
```

- **Domain:** `teams.microsoftonline-sharepoint.online`
- **Technique:** Combosquat domain (microsoftonline-sharepoint[.]online) serving a "Teams Meeting - Join Now" lure that funnels to credential capture
- **Detection:** DNS/proxy regex for hostnames containing both 'microsoftonline' and 'sharepoint' outside *.microsoft.com / *.sharepoint.com; flag .online TLD + Teams meeting keywords
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/a341bead-3759-439f-b533-1fe9957caaf8/
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0667 — Microsoft

```text
http://microsoftturkey.com
```

- **Domain:** `microsoftturkey.com`
- **Technique:** Typosquat/brand-impersonation domain serving a fake "Microsoft | Regional Endpoint — Turkey" gate page used as a first-stage redirector to sign-in phish
- **Detection:** Hunt for Microsoft brand + country/region-name domain registrations (microsoft<country>.tld) with no Microsoft ASN or certificate; plaintext HTTP on a 'Microsoft' host is itself an indicator
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/7966b103-e21b-4b72-bc8d-5ddd39951061/
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0668 — Microsoft

```text
http://microsoftturkiye.com
```

- **Domain:** `microsoftturkiye.com`
- **Technique:** Sibling typosquat of microsoftturkey[.]com — identical "Microsoft | Regional Endpoint — Turkey" gate page (same 1452-byte payload), indicating one actor-controlled cluster
- **Detection:** Pivot on exact HTTP response body length / page title 'Microsoft | Regional Endpoint' to surface the rest of the cluster; correlate shared registrar and hosting IP
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/cd8c1c94-15c4-4848-8454-d3fe77830d9b/
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0669 — Microsoft OneDrive

```text
http://projectshare.ngrok.pro/OneDrive.html
```

- **Domain:** `projectshare.ngrok.pro`
- **Technique:** HTML credential-phish page ("OneDrive — Secure Document Access") hosted behind an ngrok tunnel to rotate infrastructure and dodge domain takedowns
- **Detection:** Block/alert on all *.ngrok.pro, *.ngrok.io, *.ngrok-free.app, *.trycloudflare.com in web proxy — tunnel services have no legitimate role in Microsoft auth flows; add a rule for the filename OneDrive.html on non-Microsoft hosts
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/9744607b-0bf8-48ec-8264-a40d60749451/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0670 — Microsoft SharePoint / Outlook

```text
https://www.sharepoint-eight-alpha.vercel.app/
```

- **Domain:** `www.sharepoint-eight-alpha.vercel.app`
- **Technique:** Vercel-hosted SharePoint document lure that exfiltrates captured credentials via the EmailJS SaaS API, then redirects the victim to the real https://outlook.live.com/ to mask the theft
- **Detection:** High-fidelity: alert on any browser request to api.emailjs.com originating from a page that rendered a Microsoft sign-in form — legitimate Microsoft auth never calls EmailJS. Also flag post-auth redirects to outlook.live.com from non-Microsoft origins
- **Source:** OpenPhish (public feed) — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0671 — Microsoft Outlook Web App (OWA) / Exchange

```text
https://owalotte.net/owa/
```

- **Domain:** `owalotte.net`
- **Technique:** Lookalike domain hosting a fake OWA /owa/ sign-in path behind Cloudflare; now serving Cloudflare's own "Suspected Phishing" interstitial, confirming the verdict
- **Detection:** Hunt the URI path /owa/ or /owa/auth/logon.aspx on any host that is not your own Exchange/Entra namespace; combine with Cloudflare-fronted newly-seen domains containing 'owa'
- **Source:** OpenPhish (public feed) — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0672 — Microsoft (login page)

```text
https://aminsheikh72.github.io/microsoft-2/
```

- **Domain:** `aminsheikh72.github.io`
- **Technique:** Free GitHub Pages hosting of a cloned Microsoft sign-in page (page title literally "Microsoft login page") — abuse of a trusted, TLS-valid, high-reputation domain
- **Detection:** Alert on *.github.io URLs whose path contains microsoft/office/outlook/onedrive; GitHub Pages is never a valid Microsoft auth origin, so treat any Microsoft-branded form there as phishing
- **Source:** OpenPhish (public feed) — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0673 — Microsoft Office 365

```text
https://office365-ff2ac.web.app
```

- **Domain:** `office365-ff2ac.web.app`
- **Technique:** Firebase-hosted dynamic open-redirector: obfuscated JS polls api.telegram.org/bot<token>/getUpdates to pull the current phishing destination at runtime, falling back to a benign Google search if the bot is dead
- **Detection:** Very high-fidelity: any client-side fetch to api.telegram.org/bot*/getUpdates from a browser page is malicious. Also flag Firebase *.web.app / *.firebaseapp.com hosts matching /o(ffice|365)/i — note the related office365-ff2ac.firebaseapp.com is the same project
- **Source:** PhishDestroy — https://phishdestroy.io/domain/office365-ff2ac.web.app/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0674 — Microsoft Outlook / Microsoft 365

```text
https://outlooksa.vercel.app
```

- **Domain:** `outlooksa.vercel.app`
- **Technique:** Credential-harvesting fake Outlook sign-in hosted on free Vercel subdomain
- **Detection:** Alert on *.vercel.app hostnames containing outlook/office/onedrive/microsoft tokens in proxy and DNS logs
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0675 — Microsoft SharePoint / OneDrive

```text
https://sharepnt.ngrok.pro/OneDrive.html
```

- **Domain:** `sharepnt.ngrok.pro`
- **Technique:** Static OneDrive.html credential page tunnelled through ngrok reverse proxy
- **Detection:** Block/alert on *.ngrok.pro and *.ngrok.app egress; hunt HTTP GETs for /OneDrive.html on non-Microsoft hosts
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0676 — Microsoft Hotmail / Outlook.com

```text
https://api.hotmail666.com
```

- **Domain:** `api.hotmail666.com`
- **Technique:** Typosquat brand domain serving fake Hotmail/Outlook logon
- **Detection:** Regex DNS for ^.*hotmail[0-9]+\. and any non-Microsoft registrable domain containing 'hotmail'
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0677 — Microsoft Hotmail / Outlook.com

```text
https://usdt.hotmail666.com
```

- **Domain:** `usdt.hotmail666.com`
- **Technique:** Sibling subdomain of hotmail666[.]com phishing cluster
- **Detection:** Pivot on passive DNS for all subdomains of hotmail666.com and block the apex
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0678 — Microsoft 365

```text
http://microsoft.o356.ee/0ekxrgqe64d9e4vz
```

- **Domain:** `microsoft.o356.ee`
- **Technique:** Homoglyph/typosquat 'o356' (Office 365) with per-victim random path token
- **Detection:** Hunt URLs where 'microsoft' appears as a subdomain of a non-Microsoft apex, plus 16-char lowercase alnum paths
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0679 — Microsoft Outlook

```text
https://outlook-mailer.com/signin
```

- **Domain:** `outlook-mailer.com`
- **Technique:** Fake Outlook signin endpoint with JWT-style ?t= victim token (AiTM-style prefilled email)
- **Detection:** Alert on /signin?t=eyJ* JWT-looking query params on non-Microsoft hosts
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0682 — Microsoft Office / Microsoft 365

```text
https://login.microsoftofice.cz/runner.html
```

- **Domain:** `login.microsoftofice.cz`
- **Technique:** ClickFix fake 'verify you are human' page on single-letter typosquat (microsoftofice) leading to RAT via Windows Run dialog
- **Detection:** Hunt clipboard-write + Win+R execution after web browse; block *.microsoftofice.cz and IP 209.38.249.166
- **Source:** Security Boulevard / CyberProof research — https://securityboulevard.com/2026/11/inside-a-microsoft-lookalike-domain-masquerading-as-czech-companys-it-department-infrastructure/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0683 — Microsoft Office / Microsoft 365

```text
https://login.microsoftofice.cz/pass.html
```

- **Domain:** `login.microsoftofice.cz`
- **Technique:** Credential/password page on the microsoftofice[.]cz lookalike IT-department infrastructure
- **Detection:** Alert on any host matching microsoft(o|)fice*.cz and on beacon GETs to /lokopoko.php?name=
- **Source:** Security Boulevard / CyberProof research — https://securityboulevard.com/2026/11/inside-a-microsoft-lookalike-domain-masquerading-as-czech-companys-it-department-infrastructure/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0684 — Microsoft Entra ID / microsoftonline

```text
https://authenticate-microsoftonline.com
```

- **Domain:** `authenticate-microsoftonline.com`
- **Technique:** Newly registered combosquat of login.microsoftonline.com for sign-in harvesting
- **Detection:** CT-log monitor for new certs containing 'microsoftonline' outside Microsoft-owned CAA/registrant
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0685 — Microsoft Entra ID

```text
https://auth-microsoft.app
```

- **Domain:** `auth-microsoft.app`
- **Technique:** Newly registered auth-themed combosquat on .app TLD
- **Detection:** Block newly observed domains matching ^(auth|login|sso|mfa)[-.]microsoft
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0686 — Microsoft Entra ID / microsoftonline

```text
https://microsoftoine.com
```

- **Domain:** `microsoftoine.com`
- **Technique:** Character-drop typosquat of 'microsoftonline' (missing 'nl')
- **Detection:** Run Levenshtein<=3 fuzzy match of new registrations against microsoftonline.com
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0687 — Microsoft 365 support

```text
https://microsoft-support-center.com
```

- **Domain:** `microsoft-support-center.com`
- **Technique:** Tech-support themed lookalike used for sign-in and callback lures
- **Detection:** Alert on new 'microsoft-*support*' registrations; correlate with inbound help-desk-themed mail
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0688 — Microsoft 365

```text
https://microsoft365api.com
```

- **Domain:** `microsoft365api.com`
- **Technique:** API-themed combosquat posing as Microsoft 365 service endpoint
- **Detection:** Treat any non-Microsoft apex containing 'microsoft365' as high-risk in DNS filtering
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0689 — Microsoft

```text
https://microsoftup.top
```

- **Domain:** `microsoftup.top`
- **Technique:** Cheap-TLD (.top) Microsoft combosquat for update/sign-in lures
- **Detection:** Score .top/.sbs/.cyou/.buzz registrations containing 'microsoft' as malicious by default
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0690 — Microsoft Outlook

```text
https://outlook-verify-session.top
```

- **Domain:** `outlook-verify-session.top`
- **Technique:** Session-expiry lure combosquat (AiTM session-theft theme)
- **Detection:** Hunt hostnames combining outlook/office with verify|session|expired|reauth
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0691 — Microsoft Outlook

```text
https://outlookmailbox.com
```

- **Domain:** `outlookmailbox.com`
- **Technique:** Mailbox-quota/validation themed Outlook lookalike
- **Detection:** Block Outlook-branded apexes; alert on 'mailbox full / revalidate' mail pointing offsite
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0692 — Microsoft 365 support

```text
https://microsoftsupport.digital
```

- **Domain:** `microsoftsupport.digital`
- **Technique:** Support-portal lookalike on .digital, same pattern as microsoftsupportcenter.digital cluster
- **Detection:** Pivot on registrar/NS of known *.digital Microsoft-support squats and block the whole set
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0693 — Microsoft

```text
https://care-microsoft.com
```

- **Domain:** `care-microsoft.com`
- **Technique:** Customer-care themed Microsoft combosquat
- **Detection:** Alert on new registrations of ^(care|help|desk|service)-microsoft
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0694 — Microsoft Hotmail / Outlook.com

```text
https://hotmaill.live
```

- **Domain:** `hotmaill.live`
- **Technique:** Doubled-letter typosquat of hotmail on .live (mimics Microsoft Live branding)
- **Detection:** Fuzzy-match new .live registrations against hotmail.com/live.com
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0695 — Microsoft Outlook

```text
https://outlook-verif.com
```

- **Domain:** `outlook-verif.com`
- **Technique:** Truncated 'verification' combosquat (French-language lure pattern)
- **Detection:** Hunt outlook-/office- prefixed domains with truncated verb stems (verif, confirm, valid)
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0696 — Microsoft OneDrive

```text
https://onedrivedocs.xn--q9jyb4c
```

- **Domain:** `onedrivedocs.xn--q9jyb4c`
- **Technique:** IDN/punycode TLD abuse for a OneDrive document-share credential lure
- **Detection:** Flag all xn-- hostnames in proxy logs, especially combined with brand strings
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0697 — Microsoft Office 365

```text
https://office365online.com
```

- **Domain:** `office365online.com`
- **Technique:** Combosquat merging 'office365' + 'online' to mimic the real sign-in host
- **Detection:** Block non-Microsoft apexes containing both 'office365' and 'online'
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0698 — Microsoft Outlook

```text
https://outlookts.com
```

- **Domain:** `outlookts.com`
- **Technique:** Short-suffix Outlook typosquat used for webmail credential pages
- **Detection:** Fuzzy-match outlook.com with 1-3 appended characters in new registrations
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0699 — Microsoft Outlook / Safe Links

```text
https://saferlink-outlook.com
```

- **Domain:** `saferlink-outlook.com`
- **Technique:** Impersonates Microsoft Defender Safe Links to launder redirects to a fake sign-in
- **Detection:** Any 'safelink'/'saferlink' host not under *.safelinks.protection.outlook.com is malicious
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0700 — Microsoft Office 365

```text
https://microsoftoffice365.top
```

- **Domain:** `microsoftoffice365.top`
- **Technique:** Full-brand-string combosquat on cheap .top TLD
- **Detection:** Deny-list exact brand concatenations (microsoftoffice365) on any non-Microsoft TLD
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-0701 — Microsoft OneDrive / MSA

```text
https://onedrives-msa-document-access.online
```

- **Domain:** `onedrives-msa-document-access.online`
- **Technique:** Long descriptive document-share lure embedding 'msa' (Microsoft Account) sign-in theme
- **Detection:** Hunt hostnames with 3+ hyphen-separated tokens mixing onedrive/msa/document/access
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0702 — Microsoft OneDrive

```text
https://onedrive-sync.top
```

- **Domain:** `onedrive-sync.top`
- **Technique:** Sync-error lure combosquat prompting re-authentication
- **Detection:** Alert on onedrive-* registrations on .top/.online/.site TLDs
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0703 — Microsoft

```text
https://updtes-microsoft.com
```

- **Domain:** `updtes-microsoft.com`
- **Technique:** Misspelled 'updates' combosquat for security-update sign-in lures
- **Detection:** Detect misspelled common-word prefixes (updtes, verifiy, securty) paired with brand names
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0704 — Microsoft Security / Defender

```text
https://microsofty-security.com
```

- **Domain:** `microsofty-security.com`
- **Technique:** Appended-letter typosquat with security-alert sign-in lure
- **Detection:** Fuzzy-match microsoft.com +1 char; pair with 'security|defender|alert' tokens
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0705 — Microsoft Defender

```text
https://defend-microsoft.com
```

- **Domain:** `defend-microsoft.com`
- **Technique:** Defender-branded combosquat for threat-alert credential lures
- **Detection:** Alert on (defend|defender|protect)-microsoft registrations outside Microsoft registrant
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-0706 — Microsoft OneDrive / Live

```text
https://folder-onedrive-live.com
```

- **Domain:** `folder-onedrive-live.com`
- **Technique:** Shared-folder lure combosquat mixing onedrive + live branding
- **Detection:** Hunt hostnames containing 'live' plus a Microsoft product token on non-Microsoft apexes
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0707 — Microsoft Outlook / Microsoft Account

```text
https://accounts-outlook.com
```

- **Domain:** `accounts-outlook.com`
- **Technique:** Account-portal combosquat mimicking Microsoft account sign-in
- **Detection:** Block ^(account|accounts)[-.](outlook|microsoft|office) new registrations
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0708 — Microsoft Account Protection

```text
https://accountprotection-microsofts.click
```

- **Domain:** `accountprotection-microsofts.click`
- **Technique:** Bulk-registered 'account protection' squat sprayed across 14+ cheap TLDs
- **Detection:** Block the second-level label accountprotection-microsofts across ALL TLDs, not per-domain
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0709 — Microsoft Account Protection

```text
https://accountprotection-microsofts.website
```

- **Domain:** `accountprotection-microsofts.website`
- **Technique:** Same bulk TLD-spray cluster; fake unusual-sign-in security alert
- **Detection:** Pivot on shared NS/registrant to enumerate the full TLD spray set and block as a group
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0710 — Microsoft Account Protection

```text
https://accountprotection-microsofts.store
```

- **Domain:** `accountprotection-microsofts.store`
- **Technique:** Bulk TLD-spray squat of account.protection.microsoft branding
- **Detection:** Treat 'microsofts' (plural) as a high-confidence squat token in DNS rules
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0711 — Microsoft Account Protection

```text
https://accountprotection-microsofts.sbs
```

- **Domain:** `accountprotection-microsofts.sbs`
- **Technique:** Bulk TLD-spray squat on .sbs
- **Detection:** Block .sbs/.cyou/.monster/.buzz entirely at the resolver if business need is absent
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0712 — Microsoft Account Protection

```text
https://accountprotection-microsofts.monster
```

- **Domain:** `accountprotection-microsofts.monster`
- **Technique:** Bulk TLD-spray squat on .monster
- **Detection:** Alert on first-seen resolution of any accountprotection-* host from corporate endpoints
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0713 — Microsoft Account Protection

```text
https://accountprotection-microsofts.cyou
```

- **Domain:** `accountprotection-microsofts.cyou`
- **Technique:** Bulk TLD-spray squat on .cyou
- **Detection:** Correlate CT-log issuance bursts of identical SANs across TLDs to catch the whole cluster early
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0714 — Microsoft Account Protection

```text
https://accountprotection-microsofts.buzz
```

- **Domain:** `accountprotection-microsofts.buzz`
- **Technique:** Bulk TLD-spray squat on .buzz
- **Detection:** Hunt mail with 'account protection' subject lines whose links leave Microsoft-owned domains
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0715 — Microsoft Outlook

```text
https://notification-outlook.com
```

- **Domain:** `notification-outlook.com`
- **Technique:** Notification-themed Outlook combosquat for sign-in harvesting
- **Detection:** Block (notification|notifications|alert)-outlook registrations
- **Source:** phishunt.io (newly registered) — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-10-29

### mfs-0716 — Microsoft 365

```text
https://off365acess.jumpingcrab.com
```

- **Domain:** `off365acess.jumpingcrab.com`
- **Technique:** SkyW4lker phishing kit node abusing OAuth 2.0 device-code flow (T1528) on free dynamic-DNS host
- **Detection:** Monitor Entra ID sign-in logs for unexpected device-code auth; alert on *.jumpingcrab.com, *.mooo.com, *.chickenkiller.com egress
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0717 — Microsoft 365

```text
https://torvion.life
```

- **Domain:** `torvion.life`
- **Technique:** SkyW4lker kit hosting domain; landing path matches //it[A-Za-z0-9]{32}us
- **Detection:** Hunt proxy URIs matching /assets/php/endpoints/session_public.php?action=start|poll
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0718 — Microsoft 365

```text
https://priorispace.biz
```

- **Domain:** `priorispace.biz`
- **Technique:** SkyW4lker kit hosting domain with CAPTCHA/sandbox evasion before the M365 logon clone
- **Detection:** Alert on requests to /assets/private_captcha/public/widget.js?v=4 and /assets/js/client_geo.js
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0719 — Microsoft 365

```text
https://5200m.com
```

- **Domain:** `5200m.com`
- **Technique:** SkyW4lker kit hosting domain reached via Google Sites / Smartsheet redirect chains
- **Detection:** Flag Google Sites and Smartsheet links that hop to unrelated low-reputation apexes
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0720 — Microsoft 365

```text
https://ghethim.com
```

- **Domain:** `ghethim.com`
- **Technique:** SkyW4lker kit hosting domain; obfuscator.io-packed JS credential capture
- **Detection:** Hunt /assets/js/endpoint.js and /assets/js/url_helper.js URI pairs on non-Microsoft hosts
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0721 — Microsoft 365

```text
https://flow505.mooo.com
```

- **Domain:** `flow505.mooo.com`
- **Technique:** SkyW4lker kit node on FreeDNS dynamic-DNS subdomain
- **Detection:** Block free dynamic-DNS parents (mooo.com, chickenkiller.com, jumpingcrab.com) at the resolver
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0722 — Microsoft 365

```text
https://bigbrain.chickenkiller.com
```

- **Domain:** `bigbrain.chickenkiller.com`
- **Technique:** SkyW4lker kit node delivered via password-protected PDF/XLS/DOCX attachments
- **Detection:** Quarantine password-protected attachments with subjects 'New Submission From' / 'Approved Statement'
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-10-27

### mfs-0723 — Microsoft Outlook

```text
https://outlook40394343.web.app/
```

- **Domain:** `outlook40394343.web.app`
- **Technique:** Credential-harvesting fake Outlook sign-in hosted on Firebase/Google web.app free hosting (page title 'Sample Background')
- **Detection:** Alert on HTTP/DNS to *.web.app hosts whose subdomain contains 'outlook'/'office'/'onedrive' plus a long digit string; these are near-never legitimate business destinations
- **Source:** PhishDestroy — https://phishdestroy.io/domain/outlook40394343.web.app/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0724 — Microsoft Outlook

```text
https://outlook40394343.firebaseapp.com/
```

- **Domain:** `outlook40394343.firebaseapp.com`
- **Technique:** Same kit as the .web.app twin — Firebase-hosted fake Outlook login; firebaseapp.com is the paired default domain for the same Firebase project
- **Detection:** When one *.web.app phish is found, always block the identical *.firebaseapp.com label (and vice versa) — Firebase serves both from one project
- **Source:** PhishDestroy — https://phishdestroy.io/domain/outlook40394343.firebaseapp.com/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0725 — Microsoft SharePoint / OneDrive

```text
https://sharepoint.onedrive.dczhxkw84930320.passkey.auth02.outlook.drive.plastkon.cc
```

- **Domain:** `sharepoint.onedrive.dczhxkw84930320.passkey.auth02.outlook.drive.plastkon.cc`
- **Technique:** Deep subdomain-chain impersonation ('ShareP0int' page) on an attacker-registered .cc domain, with fake passkey/auth labels to push the real domain off the visible URL bar
- **Detection:** Hunt DNS/proxy logs for FQDNs with 4+ labels mixing sharepoint/onedrive/outlook/passkey/auth where the registrable domain is not microsoft.com; alert on label count > 5 with Microsoft keywords
- **Source:** PhishDestroy — https://phishdestroy.io/domain/sharepoint.onedrive.dczhxkw84930320.passkey.auth02.outlook.drive.plastkon.cc/
- **Status:** active
- **First seen:** 2026-10-20

### mfs-0726 — Microsoft Account / Live

```text
https://verificarcuenta-micros0ft2026way.zya.me/?i=1
```

- **Domain:** `verificarcuenta-micros0ft2026way.zya.me`
- **Technique:** Spanish-language 'verify your account' typosquat (micros0ft with a zero) on free zya.me dynamic-DNS hosting
- **Detection:** Regex Microsoft homoglyph/leetspeak variants (micr0soft, micros0ft, rnicrosoft) against proxy and email URL logs; add free hosts zya.me / yzz.me / iceiy.com / hstn.me to a high-risk TLD-host watchlist
- **Source:** phishunt.io (hourly Microsoft phishing tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0727 — Microsoft 365 / Entra ID

```text
https://goldcreekconcrete.com
```

- **Domain:** `goldcreekconcrete.com`
- **Technique:** SkyW4lker ('x365 Sentinel') device-code phishing landing on a Microsoft-themed subdomain chain — victim is shown a real Entra device code to enter at login.microsoft.com/device, yielding a valid session with no password or MFA bypass
- **Detection:** Hunt web proxy for /assets/php/endpoints/session_public.php?action=start and repeated ?action=poll; correlate Entra ID device-code sign-ins against users who received password-protected invoice/contract attachments minutes earlier
- **Source:** Cyber Security News / ANY.RUN research — https://cybersecuritynews.com/skyw4lker-phishing-campaign-expands-threatening-us-enterprises-with-microsoft-365-account-takeovers/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0728 — Microsoft 365 / Entra ID

```text
https://goldcreekconcrete.org
```

- **Domain:** `goldcreekconcrete.org`
- **Technique:** SkyW4lker device-code phishing — .org sibling of the same actor-controlled domain pair, serving the same landing tokens (//it[A-Za-z0-9]{32}us)
- **Detection:** Block both TLD variants together; alert on URL paths matching //it[A-Za-z0-9]{32}us or //zt[A-Za-z0-9]{32}op and on Conditional Access policies not yet restricting device-code flow
- **Source:** Cyber Security News / ANY.RUN research — https://cybersecuritynews.com/skyw4lker-phishing-campaign-expands-threatening-us-enterprises-with-microsoft-365-account-takeovers/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0729 — Microsoft 365 / Entra ID

```text
https://openai.eventrsvp.app
```

- **Domain:** `openai.eventrsvp.app`
- **Technique:** Fake OpenAI Academy event RSVP page with 'Continue with Microsoft' button feeding Kali365 device-code phishing
- **Detection:** Alert on Entra sign-in logs showing successful device code flow (authenticationProtocol=deviceCode) from an IP that never previously authenticated for that user
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0730 — Microsoft 365 / Entra ID

```text
https://spacex.eventrsvp.app
```

- **Domain:** `spacex.eventrsvp.app`
- **Technique:** Fake SpaceX AI briefing RSVP lure chaining to Kali365 Microsoft device-code phishing
- **Detection:** Block *.eventrsvp.app at the proxy; hunt URL pattern /event/<brand>/id<11 digits>/rsvp/ in web logs
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0731 — Microsoft 365 / Entra ID

```text
https://anthropic.rsvpconnect-events.com
```

- **Domain:** `anthropic.rsvpconnect-events.com`
- **Technique:** Fake 'Anthropic at AWS re:Invent' event page offering Microsoft SSO that drives device-code consent
- **Detection:** Flag newly registered domains containing 'rsvp'/'event' resolving to the same ASN as the eventrsvp.app cluster
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0732 — Microsoft 365 / Entra ID

```text
https://register.rsvpconnect-events.com
```

- **Domain:** `register.rsvpconnect-events.com`
- **Technique:** Registration-stage lure host in the AI-event campaign preceding the Microsoft sign-in relay
- **Detection:** Correlate egress to rsvpconnect-events.com with a device-code sign-in inside 15 minutes
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0733 — Microsoft 365 / Entra ID

```text
https://62zr4vcasl.shifts.icu/api/generate?lure=candidate-portal-JhI3
```

- **Domain:** `62zr4vcasl.shifts.icu`
- **Technique:** Kali365 PhaaS backend API that mints Microsoft device codes on demand for the lure pages
- **Detection:** Block .icu TLD or alert on POST/GET to /api/generate?lure= on random 10-char subdomains
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0734 — Microsoft Office 365

```text
https://continue-to-office-.ggleventapi.icu
```

- **Domain:** `continue-to-office-.ggleventapi.icu`
- **Technique:** AiTM relay host presenting the Microsoft sign-in continuation step after the device code is displayed
- **Detection:** Hunt DNS for subdomains starting 'continue-to-office' across all TLDs
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0735 — Microsoft 365 SSO

```text
https://login.wbdssologin.app
```

- **Domain:** `login.wbdssologin.app`
- **Technique:** Fake corporate SSO portal proxying the Microsoft sign-in flow (AiTM)
- **Detection:** Block .app domains containing 'ssologin'; alert on sign-ins with referrer not in login.microsoftonline.com
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0736 — Microsoft 365 SSO

```text
https://wbdssologin.app
```

- **Domain:** `wbdssologin.app`
- **Technique:** Apex of the fake SSO relay domain used in the AI-event Microsoft phishing chain
- **Detection:** Certificate Transparency monitoring for 'ssologin' + brand-abbreviation registrations
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0737 — Microsoft Office 365

```text
https://nextconfirmationlogin.officegocrqb.com
```

- **Domain:** `nextconfirmationlogin.officegocrqb.com`
- **Technique:** Office-themed AiTM sign-in confirmation page harvesting credentials and session tokens
- **Detection:** Regex DNS/proxy logs for hostnames matching (login|signin|confirmation).*office.{4,8}\.com
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0738 — Microsoft Office 365

```text
https://continueevenregistration.officegocrqb.com
```

- **Domain:** `continueevenregistration.officegocrqb.com`
- **Technique:** Event-registration pivot host on the officegocrqb AiTM infrastructure
- **Detection:** Block the whole officegocrqb.com zone, not just observed subdomains
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0739 — Microsoft 365 SSO

```text
https://continuessoevent.officegocrqb.com
```

- **Domain:** `continuessoevent.officegocrqb.com`
- **Technique:** Fake 'continue with SSO' step relaying to the real Microsoft login (AiTM)
- **Detection:** Wildcard-block *.officegocrqb.com; alert on token issuance following traffic to it
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0740 — Microsoft 365

```text
https://signincomplete.offcevent-login.com
```

- **Domain:** `signincomplete.offcevent-login.com`
- **Technique:** Typosquat ('offce') sign-in completion page in the device-code/AiTM chain
- **Detection:** Hunt for 'offce'/'0ffice'/'ofice' character-omission typosquats in NRD feeds
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0741 — Microsoft 365

```text
https://offcevent-login.com
```

- **Domain:** `offcevent-login.com`
- **Technique:** Office typosquat apex hosting the fake Microsoft sign-in relay
- **Detection:** Block domain; add 'offcevent' string to SIEM watchlist
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0742 — Microsoft SharePoint / Office 365

```text
https://office.com-access-sharepoint.com
```

- **Domain:** `office.com-access-sharepoint.com`
- **Technique:** Subdomain-deception domain making 'office.com' appear to be the registrable name
- **Detection:** Alert on any hostname where a legitimate brand FQDN appears left of a different registrable domain
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0743 — Microsoft 365 / Entra ID

```text
https://eventrsvp-217-60-102-48.sslip.io/collect.php
```

- **Domain:** `eventrsvp-217-60-102-48.sslip.io`
- **Technique:** sslip.io wildcard-DNS collection endpoint exfiltrating harvested data from the lure pages
- **Detection:** Block *.sslip.io and *.nip.io wildcard-DNS services; alert on POSTs to /collect.php
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0744 — Microsoft OneDrive

```text
https://splace.co.za/0987643345678908765421234567890987654320987654321223456787654/onedrive/
```

- **Domain:** `splace.co.za`
- **Technique:** Quishing — QR code embedded in a Word 'salary review' attachment leading to a fake OneDrive sign-in portal plus device-code relay
- **Detection:** Hunt Microsoft-themed paths on unrelated ccTLD hosts with long all-numeric path segments; scan inbound Office attachments for QR images
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/05/email-threat-landscape-q3-2026-trends-and-insights/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0745 — Microsoft 365 / Outlook

```text
https://sdocshares.auth.outlook2026common.copilos26.csr-rooflng.com
```

- **Domain:** `sdocshares.auth.outlook2026common.copilos26.csr-rooflng.com`
- **Technique:** SkyW4lker x365 Sentinel device-code phishing on a deeply nested Microsoft-themed hostname chain
- **Detection:** Regex DNS logs for (docshare|sdocshares|pdocshared|efaxdoc|reauth|statement|copilot|login|auth).*(outlook|onedrive|copilot|office365)
- **Source:** ANY.RUN (via Cyber Security News) — https://cybersecuritynews.com/skyw4lker-phishing-campaign-expands-threatening-us-enterprises-with-microsoft-365-account-takeovers/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0746 — Microsoft 365 / Outlook

```text
https://pdocshared.payments2026.outlooks.common.ecmholdlnggroup.com
```

- **Domain:** `pdocshared.payments2026.outlooks.common.ecmholdlnggroup.com`
- **Technique:** SkyW4lker device-code phishing host using a lookalike ('holdlng') corporate domain with Outlook-themed subdomain chain
- **Detection:** Alert on >3-label subdomain chains mixing Microsoft service names; watch SkyW4lker URI markers /assets/php/endpoints/session_public.php?action=start
- **Source:** ANY.RUN (via Cyber Security News) — https://cybersecuritynews.com/skyw4lker-phishing-campaign-expands-threatening-us-enterprises-with-microsoft-365-account-takeovers/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0747 — Microsoft 365

```text
https://login.microsoftofice.cz/lokopoko.php?name=
```

- **Domain:** `login.microsoftofice.cz`
- **Technique:** Credential-exfiltration endpoint behind the microsoftofice.cz fake IT-department sign-in pages (two-step username/password capture)
- **Detection:** Block the microsoftofice.cz zone; alert on GET/POST to lokopoko.php and on MX microsoftofice-cz.mail.protection.outlook.com
- **Source:** Flare Research (via Security Boulevard) — https://securityboulevard.com/2026/11/inside-a-microsoft-lookalike-domain-masquerading-as-czech-companys-it-department-infrastructure/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0748 — Microsoft 365

```text
https://microsoftontine.com
```

- **Domain:** `microsoftontine.com`
- **Technique:** Homoglyph typosquat of microsoftonline.com ('ti' for 'li')
- **Detection:** Run Levenshtein-1/2 checks against microsoftonline.com over newly registered domain feeds
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0749 — Microsoft 365

```text
https://microsoftonilne-na.com
```

- **Domain:** `microsoftonilne-na.com`
- **Technique:** Character-transposition typosquat of microsoftonline ('onilne') with regional suffix
- **Detection:** Detect anagram/transposition variants of 'online' adjacent to 'microsoft' in CT logs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0750 — Microsoft 365

```text
https://login--microsoftonline.com
```

- **Domain:** `login--microsoftonline.com`
- **Technique:** Double-hyphen typosquat mimicking login.microsoftonline.com
- **Detection:** Flag registrations containing '--microsoftonline' or hyphen-substituted brand FQDNs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0751 — Microsoft 365

```text
https://microsoft365emailessentials.online
```

- **Domain:** `microsoft365emailessentials.online`
- **Technique:** Brand-keyword squat posing as a Microsoft 365 email service sign-in
- **Detection:** Watch .online/.site TLDs with 'microsoft365' + mail keywords
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0752 — Microsoft Live / Hotmail

```text
https://hotmaill.shop
```

- **Domain:** `hotmaill.shop`
- **Technique:** Doubled-letter typosquat of hotmail.com targeting consumer Microsoft account sign-in
- **Detection:** Monitor doubled-consonant variants of hotmail/outlook across cheap commerce TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0753 — Microsoft

```text
https://cdn-microsoft.top
```

- **Domain:** `cdn-microsoft.top`
- **Technique:** Fake Microsoft CDN host used to serve sign-in/credential pages and payloads
- **Detection:** Block .top TLD or alert on 'cdn-microsoft'/'microsoft-cdn' hostnames not in Microsoft ASNs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0754 — Microsoft Outlook

```text
https://outlook-s.com
```

- **Domain:** `outlook-s.com`
- **Technique:** Outlook brand squat hosting webmail sign-in impersonation
- **Detection:** Alert on any non-Microsoft-ASN domain beginning 'outlook-'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0755 — Microsoft Outlook

```text
https://rustic-outlook.com
```

- **Domain:** `rustic-outlook.com`
- **Technique:** Adjective-prefixed Outlook squat typical of auto-generated phishing hosts
- **Detection:** Hunt NRDs matching ^[a-z]+-outlook\.(com|net|org)$
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0756 — Microsoft Outlook

```text
https://notes-to-outlook.com
```

- **Domain:** `notes-to-outlook.com`
- **Technique:** Fake migration/notes-to-Outlook utility used as a credential-harvest pretext
- **Detection:** Flag 'to-outlook'/'migrate-outlook' domains; inspect for embedded Microsoft sign-in iframes
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0757 — Microsoft Outlook

```text
https://outlookmailgmail.com
```

- **Domain:** `outlookmailgmail.com`
- **Technique:** Dual-brand (Outlook+Gmail) squat offering a fake mail provider chooser before Microsoft credential capture
- **Detection:** Alert on single domains concatenating two mail-provider brand names
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0758 — Microsoft Outlook

```text
https://outlookcentertop.biz
```

- **Domain:** `outlookcentertop.biz`
- **Technique:** Fake 'Outlook center' portal on a low-reputation .biz registration
- **Detection:** Block .biz NRDs containing 'outlook'; check for /owa or /login paths
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0759 — Microsoft 365 / Outlook

```text
https://outlook366.com
```

- **Domain:** `outlook366.com`
- **Technique:** Numeric typosquat ('366' for '365') hosting an Outlook sign-in clone
- **Detection:** Enumerate 36x/o365/0365 numeric variants of Microsoft 365 branding in NRD feeds
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0760 — Microsoft Outlook

```text
https://outlooktracker.com
```

- **Domain:** `outlooktracker.com`
- **Technique:** Fake Outlook mail-tracking service pretext leading to sign-in capture
- **Detection:** Watch 'outlook' + utility noun (tracker/monitor/checker) registrations
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0761 — Microsoft Outlook

```text
https://outlook-info.com
```

- **Domain:** `outlook-info.com`
- **Technique:** Generic Outlook information portal squat used for credential-phishing landing pages
- **Detection:** Alert on 'outlook-info'/'outlook-support'/'outlook-help' NRDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0762 — Microsoft Outlook

```text
https://review-outlook.com
```

- **Domain:** `review-outlook.com`
- **Technique:** 'Review your Outlook account' urgency pretext squat
- **Detection:** Flag action-verb prefixes (review/verify/confirm/secure) paired with Microsoft brands
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0763 — Microsoft OneDrive

```text
https://onedriverdocument.com
```

- **Domain:** `onedriverdocument.com`
- **Technique:** OneDrive squat ('onedriver') posing as a shared-document portal requiring Microsoft sign-in
- **Detection:** Hunt 'onedriver'/'onedrve'/'onedrivee' misspellings in DNS and CT logs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0764 — Microsoft OneDrive

```text
https://onedrivedisk.com
```

- **Domain:** `onedrivedisk.com`
- **Technique:** Fake OneDrive storage portal used for file-share credential phishing
- **Detection:** Block OneDrive-keyword domains outside Microsoft ASNs; inspect for fake sign-in modal over a blurred PDF
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0765 — Microsoft OneDrive

```text
https://onedrivea.net
```

- **Domain:** `onedrivea.net`
- **Technique:** Appended-character OneDrive typosquat
- **Detection:** Detect brand+single-letter suffix patterns (onedrivea, outlooka, microsofta)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0766 — Microsoft

```text
https://microsoftsetup.com
```

- **Domain:** `microsoftsetup.com`
- **Technique:** Fake Microsoft setup/activation page prompting account sign-in
- **Detection:** Flag 'microsoft' + setup/activate/install keyword domains not owned by Microsoft (check WHOIS registrant)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0767 — Microsoft

```text
https://microsofts.network
```

- **Domain:** `microsofts.network`
- **Technique:** Pluralized brand squat on an infrastructure-themed TLD
- **Detection:** Monitor 'microsofts'/'msofts' plural variants across .network/.cloud/.online
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0768 — Microsoft

```text
https://microsoftupdate.site
```

- **Domain:** `microsoftupdate.site`
- **Technique:** Fake Microsoft update notice driving account re-authentication
- **Detection:** Block microsoftupdate* on non-Microsoft ASNs; Microsoft never serves updates from .site/.pro/.surf
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0769 — Microsoft

```text
https://microsoftupdate.pro
```

- **Domain:** `microsoftupdate.pro`
- **Technique:** Update-themed squat used for credential and tech-support style sign-in capture
- **Detection:** Same-string, multi-TLD registration clustering ('microsoftupdate' on .site/.pro/.surf) is a strong campaign signal
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0770 — Microsoft

```text
https://microsoft-update.surf
```

- **Domain:** `microsoft-update.surf`
- **Technique:** Hyphenated update-themed Microsoft squat on an unusual TLD
- **Detection:** Alert on any Microsoft-branded domain in rarely-used gTLDs (.surf, .top, .icu, .buzz)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0771 — Microsoft 365

```text
https://microsoft365essential.com
```

- **Domain:** `microsoft365essential.com`
- **Technique:** Fake Microsoft 365 plan/licensing page leading to a sign-in form
- **Detection:** Watch 'microsoft365' + plan-name keywords (essential, basic, premium, business)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0772 — Microsoft 365 / Office

```text
https://microsoft365-download-office.com
```

- **Domain:** `microsoft365-download-office.com`
- **Technique:** Fake Office download portal requiring Microsoft account authentication
- **Detection:** Flag multi-keyword chains 'microsoft365'+'download'+'office' in one registrable name
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0773 — Microsoft 365

```text
https://microsoft365s.com
```

- **Domain:** `microsoft365s.com`
- **Technique:** Pluralized Microsoft 365 typosquat
- **Detection:** Enumerate microsoft365 + single trailing char permutations and pre-block
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0774 — Microsoft

```text
https://microsofttl.com
```

- **Domain:** `microsofttl.com`
- **Technique:** Short-suffix Microsoft brand squat used for sign-in landing pages
- **Detection:** Detect 'microsoft' + 2-3 random letters, a common bulk-registration pattern
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0775 — Microsoft Office 365

```text
https://office365store.com
```

- **Domain:** `office365store.com`
- **Technique:** Fake Office 365 store/licensing front requiring Microsoft credentials
- **Detection:** Alert on 'office365' + commerce keywords (store, shop, buy, license)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0776 — Microsoft Office 365

```text
https://partner-office365.org
```

- **Domain:** `partner-office365.org`
- **Technique:** Fake Microsoft partner portal squat soliciting tenant admin sign-in
- **Detection:** Treat 'partner'/'csp'/'admin' + office365 domains as high-risk; monitor for GDAP/delegated-admin consent requests after visits
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0777 — Microsoft

```text
https://tickets-microsoft.com
```

- **Domain:** `tickets-microsoft.com`
- **Technique:** Fake Microsoft support-ticket portal pretext for credential harvesting
- **Detection:** Flag support-themed Microsoft squats (tickets, case, helpdesk) and cross-check against reported vishing callbacks
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0778 — Microsoft Live / Hotmail

```text
https://hotmailsistermail.com
```

- **Domain:** `hotmailsistermail.com`
- **Technique:** Hotmail brand-keyword squat targeting consumer Microsoft account sign-in
- **Detection:** Monitor any NRD containing 'hotmail'; Microsoft retired the brand for new services, so new registrations are near-always malicious
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0779 — Microsoft 365

```text
https://auth.login.office365.cloud.onedrive.outlook.atlarchitacts.com
```

- **Domain:** `auth.login.office365.cloud.onedrive.outlook.atlarchitacts.com`
- **Technique:** Device-code phishing (SkyW4lker kit) behind Microsoft-themed multi-label subdomain chain on look-alike corporate domain
- **Detection:** Alert on DNS/proxy hostnames with 4+ labels chaining auth|login|office365|onedrive|outlook|copilot before a non-Microsoft registrable domain; correlate with login.microsoftonline.com/common/oauth2/deviceauth hits
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0780 — Microsoft 365 / Copilot

```text
https://authorize.copilot.outlook.common.microsoft0365.atlarchitacts.com
```

- **Domain:** `authorize.copilot.outlook.common.microsoft0365.atlarchitacts.com`
- **Technique:** Device-code phishing; digit-substitution 'microsoft0365' label inside subdomain chain
- **Detection:** Regex hunt hostnames matching microsoft[0o]?365 as a subdomain label rather than registrable domain
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0781 — Microsoft 365

```text
https://copilot.login.office365outlook.cloud.onedrive.atlarchitacts.com
```

- **Domain:** `copilot.login.office365outlook.cloud.onedrive.atlarchitacts.com`
- **Technique:** Device-code phishing with self-hosted CAPTCHA gate (/assets/private_captcha/public/widget.js)
- **Detection:** Hunt web requests to /assets/private_captcha/public/widget.js?v=4 and /assets/js/client_geo.js on non-Microsoft hosts
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0782 — Microsoft 365

```text
https://reauth.copilot.common.outlook.mcloud365.atlarchitacts.com
```

- **Domain:** `reauth.copilot.common.outlook.mcloud365.atlarchitacts.com`
- **Technique:** Device-code phishing; 'reauth' lure implying session expiry
- **Detection:** Flag hostnames beginning with reauth. that resolve outside Microsoft ASNs (campaign hosted mostly on DigitalOcean)
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0783 — Microsoft 365 / Copilot

```text
https://awemode.outlookoffice365.microsoftcopilots.docshare.linnwest.us
```

- **Domain:** `awemode.outlookoffice365.microsoftcopilots.docshare.linnwest.us`
- **Technique:** Device-code phishing behind concatenated brand labels (outlookoffice365 + microsoftcopilots)
- **Detection:** Hunt concatenated brand tokens outlookoffice365 / microsoftcopilots anywhere in a hostname
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0784 — Microsoft 365 / Copilot

```text
https://copilots.outlook.cloud.microsoft.andersonelevators.com
```

- **Domain:** `copilots.outlook.cloud.microsoft.andersonelevators.com`
- **Technique:** Device-code phishing; fake 'cloud.microsoft' suffix rendered as subdomain labels
- **Detection:** Critical hunt: hostnames containing .cloud.microsoft. where the registrable domain is NOT microsoft — defeats eyeball checks
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0785 — Microsoft 365 / Copilot

```text
https://copilots.outlook.cloud.microsoft.syrosconstructlon.com
```

- **Domain:** `copilots.outlook.cloud.microsoft.syrosconstructlon.com`
- **Technique:** Device-code phishing; fake cloud.microsoft chain on typosquatted 'constructlon' (l-for-i) domain
- **Detection:** Combine the .cloud.microsoft.* subdomain rule with homoglyph l/i substitution scoring on the registrable domain
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0786 — Microsoft 365

```text
https://statement.docdriveoauth.authorized.copilot.syrosconstructlon.com
```

- **Domain:** `statement.docdriveoauth.authorized.copilot.syrosconstructlon.com`
- **Technique:** Device-code phishing with fake OAuth/statement document lure
- **Detection:** Hunt hostname labels docdriveoauth|authorized|statement preceding copilot|outlook on non-Microsoft domains
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0787 — Microsoft 365 / OneDrive

```text
https://docshare.auth.copilot.outlook.onedrive.common.earthlink-net.com
```

- **Domain:** `docshare.auth.copilot.outlook.onedrive.common.earthlink-net.com`
- **Technique:** Device-code phishing; shared-document lure, 'common' label mimicking the Entra /common tenant path
- **Detection:** Flag the literal label 'common' used as a DNS subdomain — it is a URL path in real Entra ID, never a hostname label
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0788 — Microsoft 365 / OneDrive

```text
https://docshare.auth.copilot.outlook.onedrive.common.evergreenerg.com
```

- **Domain:** `docshare.auth.copilot.outlook.onedrive.common.evergreenerg.com`
- **Technique:** Device-code phishing, shared-document lure
- **Detection:** Same docshare.auth.copilot.outlook.onedrive.* template — pivot on the exact label order to find sibling hosts
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0789 — Microsoft 365 / OneDrive

```text
https://docshare.auth.copilot.outlook.onedrive.common0.evergreenerg.com
```

- **Domain:** `docshare.auth.copilot.outlook.onedrive.common0.evergreenerg.com`
- **Technique:** Device-code phishing; 'common0' rotation of the same kit template
- **Detection:** Wildcard-block *.evergreenerg.com; operators iterate the last label (common, common0, common1…)
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0790 — Microsoft 365 / OneDrive

```text
https://docshare.auth.copilot.outlook.onedrive.common.northemheating.com
```

- **Domain:** `docshare.auth.copilot.outlook.onedrive.common.northemheating.com`
- **Technique:** Device-code phishing on typosquatted 'northem' (rn-for-m) domain
- **Detection:** Score registrable domains for rn/m and l/i homoglyph swaps, then check for Microsoft brand labels to their left
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0791 — Microsoft 365 / OneDrive

```text
https://docshare.auth.copilot.outlookonedrive.common.northemheating.com
```

- **Domain:** `docshare.auth.copilot.outlookonedrive.common.northemheating.com`
- **Technique:** Device-code phishing; concatenated 'outlookonedrive' label variant
- **Detection:** Tokenize hostname labels and split concatenated brands (outlook+onedrive) before brand-impersonation scoring
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0792 — Microsoft 365 / OneDrive

```text
https://docshare.auth2026.onedrive.outlooksdocument.csr-rooflng.com
```

- **Domain:** `docshare.auth2026.onedrive.outlooksdocument.csr-rooflng.com`
- **Technique:** Device-code phishing; year-stamped 'auth2026' label on typosquatted 'rooflng' domain
- **Detection:** Hunt hostname labels matching auth20(25|26) or documents?20(25|26) — year-stamping is a strong kit fingerprint
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0793 — Microsoft 365 / Copilot

```text
https://docshares.auth2026.outlookcommon.copilots.commm.csr-rooflng.com
```

- **Domain:** `docshares.auth2026.outlookcommon.copilots.commm.csr-rooflng.com`
- **Technique:** Device-code phishing; 'commm' padding label to evade exact-match blocklists
- **Detection:** Normalize repeated characters in hostname labels (commm→common) before blocklist comparison
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0794 — Microsoft 365 / Copilot

```text
https://sdocshares.auth.outlook.copilos26.general.csr-rooflng.com
```

- **Domain:** `sdocshares.auth.outlook.copilos26.general.csr-rooflng.com`
- **Technique:** Device-code phishing; 'copilos26' misspelled-Copilot label
- **Detection:** Wildcard-block *.csr-rooflng.com — single domain hosts many rotating SkyW4lker hostnames
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0795 — Microsoft 365 / Copilot

```text
https://sdocshares.authoutlooks.common.copilots2026.hathormson.com
```

- **Domain:** `sdocshares.authoutlooks.common.copilots2026.hathormson.com`
- **Technique:** Device-code phishing, shared-document lure
- **Detection:** Hunt label copilots?20(25|26) in any DNS position
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0796 — Microsoft 365 / SharePoint

```text
https://pdocshared.documents2026.docs.shared.ecmholdlnggroup.com
```

- **Domain:** `pdocshared.documents2026.docs.shared.ecmholdlnggroup.com`
- **Technique:** Device-code phishing; shared-document portal lure
- **Detection:** Wildcard-block *.ecmholdlnggroup.com; pivot on 'documents2026.docs.shared' label triplet
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0797 — Microsoft 365

```text
https://efaxdoc.auth.login.outlook.office365.tescoccontrols.com
```

- **Domain:** `efaxdoc.auth.login.outlook.office365.tescoccontrols.com`
- **Technique:** Device-code phishing behind eFax/voicemail document lure
- **Detection:** Flag hostnames starting efaxdoc.|efax. that chain into outlook|office365 labels
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0798 — Microsoft 365

```text
https://efaxdoc.auth.outlook2026common.copilos26.bettylnc.com
```

- **Domain:** `efaxdoc.auth.outlook2026common.copilos26.bettylnc.com`
- **Technique:** Device-code phishing; eFax lure, 'outlook2026common' concatenation
- **Detection:** Hunt label outlook20(25|26)common — unique to this kit generation
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0799 — Microsoft 365

```text
https://payapp.auth.outlook2026common.copilos26.bettylnc.com
```

- **Domain:** `payapp.auth.outlook2026common.copilos26.bettylnc.com`
- **Technique:** Device-code phishing; payment-app lure on same host domain as the eFax variant
- **Detection:** Wildcard-block *.bettylnc.com (typosquat of a legitimate '…inc' name)
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0800 — Microsoft 365

```text
https://efaxdoc.auth.outlook2026common.copilos26.ikextal-co-kr.com
```

- **Domain:** `efaxdoc.auth.outlook2026common.copilos26.ikextal-co-kr.com`
- **Technique:** Device-code phishing; fake Korean corporate domain ('-co-kr' faking a ccTLD)
- **Detection:** Flag registrable domains embedding fake ccTLD strings (-co-kr, -co-uk, -com-au) as hyphenated labels
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0801 — Microsoft 365

```text
https://pdfdocshared.auth.outlook2026common.copilos26.ikextal-co-kr.com
```

- **Domain:** `pdfdocshared.auth.outlook2026common.copilos26.ikextal-co-kr.com`
- **Technique:** Device-code phishing; PDF shared-document lure
- **Detection:** Wildcard-block *.ikextal-co-kr.com; same operator rotates pdfdocshared/efaxdoc prefixes
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0802 — Microsoft 365

```text
https://efaxdoc.auth.outlook2026common.copilos26.kone-inc.com
```

- **Domain:** `efaxdoc.auth.outlook2026common.copilos26.kone-inc.com`
- **Technique:** Device-code phishing; impersonates the KONE brand as the host domain
- **Detection:** Monitor newly registered <your-brand>-inc.com style domains carrying Microsoft subdomain chains
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0803 — Microsoft 365

```text
https://efaxdoc.documents2026.cmc.docs.shared.matchlinemechanicallc.com
```

- **Domain:** `efaxdoc.documents2026.cmc.docs.shared.matchlinemechanicallc.com`
- **Technique:** Device-code phishing; eFax + shared-docs lure
- **Detection:** Pivot on 'documents2026.*.docs.shared' label pattern across unrelated registrable domains
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0804 — Microsoft 365

```text
https://efaxdoc.documents2026.docs.shared.lakeviewscustom.com
```

- **Domain:** `efaxdoc.documents2026.docs.shared.lakeviewscustom.com`
- **Technique:** Device-code phishing; eFax + shared-docs lure
- **Detection:** Same kit template as matchlinemechanicallc — block both and hunt the template in passive DNS
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0805 — Microsoft 365

```text
https://ecosys.newdocument2026.pdfdocshared.tntileandmarbleinc.com
```

- **Domain:** `ecosys.newdocument2026.pdfdocshared.tntileandmarbleinc.com`
- **Technique:** Device-code phishing; Kyocera-ECOSYS scanner-to-email lure chained to M365 sign-in
- **Detection:** Treat scanner/MFP brand labels (ecosys, xerox, ricoh) in hostnames as phishing indicators, not IT infrastructure
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0806 — Microsoft 365

```text
https://login.microsoft365.outlook.copilotsoffice365.lntactpr.com
```

- **Domain:** `login.microsoft365.outlook.copilotsoffice365.lntactpr.com`
- **Technique:** Device-code phishing; 'lntactpr' (l-for-I) typosquat with full brand chain
- **Detection:** Highest-confidence rule: hostname begins with 'login.microsoft365.' but registrable domain is not microsoft.com
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0807 — Microsoft 365

```text
https://login.office365outlooks.microsoft.cloud-outlook.naregruop.com
```

- **Domain:** `login.office365outlooks.microsoft.cloud-outlook.naregruop.com`
- **Technique:** Device-code phishing; 'cloud-outlook' + fake microsoft label on transposed 'naregruop' domain
- **Detection:** Flag hostnames where a label equals 'microsoft' but is not the registrable domain
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0808 — Microsoft 365

```text
https://naregruop.com
```

- **Domain:** `naregruop.com`
- **Technique:** SkyW4lker host/apex domain serving Microsoft-themed device-code phishing subdomains
- **Detection:** Wildcard-block the apex; apexes in this campaign host many rotating brand subdomains
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0809 — Microsoft 365

```text
https://m365cloud.login.outlook.office365.azgymfloor.com
```

- **Domain:** `m365cloud.login.outlook.office365.azgymfloor.com`
- **Technique:** Device-code phishing behind m365cloud/login brand chain
- **Detection:** Hunt label m365cloud|m365|mcloud365 on non-Microsoft registrable domains
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0810 — Microsoft 365

```text
https://azgymfloor.com
```

- **Domain:** `azgymfloor.com`
- **Technique:** SkyW4lker apex domain hosting M365 device-code phishing subdomains
- **Detection:** Wildcard-block apex; compromised/parked SMB sites reused as phishing hosts
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0811 — Microsoft 365 / Entra ID

```text
https://outlookdrive.microsoftonline.common.oauth2.client.buycerm.com
```

- **Domain:** `outlookdrive.microsoftonline.common.oauth2.client.buycerm.com`
- **Technique:** Device-code phishing; entire Entra OAuth2 URL path rendered as DNS labels (microsoftonline.common.oauth2.client)
- **Detection:** Alert on DNS labels 'oauth2', 'microsoftonline' or 'common' appearing as hostname labels — real Entra puts these in the path
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0812 — Microsoft 365 / Copilot

```text
https://reauth.copilot.auth.outlook.mcloud365.buycerm.com
```

- **Domain:** `reauth.copilot.auth.outlook.mcloud365.buycerm.com`
- **Technique:** Device-code phishing; re-authentication lure
- **Detection:** Wildcard-block *.buycerm.com; pivot on 'mcloud365' label
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0813 — Microsoft 365 / Copilot

```text
https://reauth.copilot.auth.outlook.mcloud365.myhalnc.com
```

- **Domain:** `reauth.copilot.auth.outlook.mcloud365.myhalnc.com`
- **Technique:** Device-code phishing; re-authentication lure on 'halnc' typosquat
- **Detection:** Hunt the exact label sequence reauth.copilot.auth.outlook.mcloud365 across passive DNS
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0814 — Microsoft 365 / Copilot

```text
https://reauth.docs.copilot.auth02.outlook.mcloud365.argentventuras.com
```

- **Domain:** `reauth.docs.copilot.auth02.outlook.mcloud365.argentventuras.com`
- **Technique:** Device-code phishing; 'auth02' label mimicking Microsoft auth endpoints
- **Detection:** Flag auth0?[0-9]{1,2} labels adjacent to outlook|copilot in hostnames
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0815 — Microsoft 365 / Copilot

```text
https://outlookoffice365.microsoftcopilots.vigilantlnc.com
```

- **Domain:** `outlookoffice365.microsoftcopilots.vigilantlnc.com`
- **Technique:** Device-code phishing; concatenated brand labels on 'vigilantlnc' (l-for-i) typosquat
- **Detection:** Wildcard-block *.vigilantlnc.com and alert on 'microsoftcopilots' label
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0816 — Microsoft 365

```text
https://statement.outlookoffice365.microsoftcopilots.calmechc.net
```

- **Domain:** `statement.outlookoffice365.microsoftcopilots.calmechc.net`
- **Technique:** Device-code phishing behind a billing-statement lure
- **Detection:** Hunt 'statement'/'statements' hostname labels preceding Microsoft brand labels
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0817 — Microsoft 365

```text
https://calmechc.net
```

- **Domain:** `calmechc.net`
- **Technique:** SkyW4lker apex domain hosting M365 device-code phishing subdomains
- **Detection:** Wildcard-block apex
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0818 — Microsoft 365

```text
https://statements.outlook.office365microsoft.payment.run.stoneclty.com
```

- **Domain:** `statements.outlook.office365microsoft.payment.run.stoneclty.com`
- **Technique:** Device-code phishing; payment/statement lure, 'office365microsoft' concatenation
- **Detection:** Alert on concatenated 'office365microsoft' label; wildcard-block *.stoneclty.com
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0819 — Microsoft 365

```text
https://shared.paymentsclouds.statementsapproved.jetbusinesscapltal.com
```

- **Domain:** `shared.paymentsclouds.statementsapproved.jetbusinesscapltal.com`
- **Technique:** Device-code phishing; approved-payment lure funnelling to M365 sign-in
- **Detection:** Wildcard-block *.jetbusinesscapltal.com (l-for-i typosquat of a finance brand)
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0820 — Microsoft 365

```text
https://wsochares.authpayments.common.paid2026.bullochdirtwroks.com
```

- **Domain:** `wsochares.authpayments.common.paid2026.bullochdirtwroks.com`
- **Technique:** Device-code phishing; payment-authorization lure
- **Detection:** Hunt 'authpayments'/'paid20(25|26)' labels with a 'common' label present
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0821 — Microsoft 365 / Copilot

```text
https://sedocs.docs.payrol2026.common.copilots2026.vatrarnsformer.com
```

- **Domain:** `sedocs.docs.payrol2026.common.copilots2026.vatrarnsformer.com`
- **Technique:** Device-code phishing; payroll-document lure ('payrol2026')
- **Detection:** Hunt payrol[l]?20(25|26) labels; wildcard-block *.vatrarnsformer.com (rn-for-m typosquat)
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0822 — Microsoft 365

```text
https://0ff365access.mooo.com
```

- **Domain:** `0ff365access.mooo.com`
- **Technique:** Device-code phishing on free dynamic-DNS (FreeDNS mooo.com); leetspeak '0ff365'
- **Detection:** Block/alert on all *.mooo.com, *.chickenkiller.com, *.twilightparadox.com, *.2waky.com, *.justdied.com, *.mefound.com, *.ignorelist.com, *.qhigh.com, *.jumpingcrab.com — free dyn-DNS roots heavily used by this kit
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0823 — Microsoft 365

```text
https://bennett002.mooo.com
```

- **Domain:** `bennett002.mooo.com`
- **Technique:** Device-code phishing on free dynamic-DNS host
- **Detection:** Numbered-operator dyn-DNS labels (<name><NNN>.mooo.com) serving M365 sign-in pages
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0824 — Microsoft 365

```text
https://0utlook0ffice365admin.twilightparadox.com
```

- **Domain:** `0utlook0ffice365admin.twilightparadox.com`
- **Technique:** Device-code phishing; zero-for-o leetspeak admin-portal lure on free dyn-DNS
- **Detection:** Normalize 0→o and 1→l in hostname labels before brand matching
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0825 — Microsoft 365

```text
https://office0365login.2waky.com
```

- **Domain:** `office0365login.2waky.com`
- **Technique:** Device-code phishing; 'office0365login' leetspeak label on free dyn-DNS
- **Detection:** Hunt office0?365 variants on dynamic-DNS roots
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0826 — Microsoft 365

```text
https://off365mail.club
```

- **Domain:** `off365mail.club`
- **Technique:** Device-code phishing; 'off365' typosquat on cheap .club TLD
- **Detection:** Hunt registrable domains matching 0?ff(ice)?365 across .club/.icu/.cc/.online TLDs
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0827 — Microsoft 365

```text
https://flow55.chickenkiller.com
```

- **Domain:** `flow55.chickenkiller.com`
- **Technique:** Device-code phishing on FreeDNS; sibling of the known flow505.mooo.com host
- **Detection:** Pivot on 'flow<digits>' dyn-DNS labels; block *.chickenkiller.com
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0828 — Microsoft 365

```text
https://swiftii.chickenkiller.com
```

- **Domain:** `swiftii.chickenkiller.com`
- **Technique:** Device-code phishing on FreeDNS dynamic-DNS host
- **Detection:** Block *.chickenkiller.com at DNS layer; no legitimate enterprise use
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0829 — Microsoft 365

```text
https://kilishy.qhigh.com
```

- **Domain:** `kilishy.qhigh.com`
- **Technique:** Device-code phishing on free dynamic-DNS host
- **Detection:** Block *.qhigh.com; hunt /assets/php/endpoints/session_public.php?action=poll requests
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0830 — Microsoft 365

```text
https://linking.mefound.com
```

- **Domain:** `linking.mefound.com`
- **Technique:** Device-code phishing redirector on free dynamic-DNS host
- **Detection:** Block *.mefound.com; alert on session_public.php?action=start in proxy logs
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0831 — Microsoft 365

```text
https://gregor.justdied.com
```

- **Domain:** `gregor.justdied.com`
- **Technique:** Device-code phishing on free dynamic-DNS host
- **Detection:** Block *.justdied.com
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0832 — Microsoft 365

```text
https://atlantictriad.ignorelist.com
```

- **Domain:** `atlantictriad.ignorelist.com`
- **Technique:** Device-code phishing on free dynamic-DNS host impersonating a company name
- **Detection:** Block *.ignorelist.com; alert when a dyn-DNS label matches a customer/partner company name
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0833 — Microsoft 365

```text
https://auth-loadingdocuments.online
```

- **Domain:** `auth-loadingdocuments.online`
- **Technique:** Device-code phishing; generic 'loading documents' interstitial before M365 sign-in
- **Detection:** Hunt newly registered .online domains combining auth|login with document|loading tokens
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0834 — Microsoft 365

```text
https://eccentric-authentication.com
```

- **Domain:** `eccentric-authentication.com`
- **Technique:** SkyW4lker backend/auth infrastructure domain for device-code flow
- **Detection:** Block apex; hunt outbound POSTs to /assets/js/endpoint.js hosts
- **Source:** ANY.RUN — https://any.run/cybersecurity-blog/skyw4lker-phishing-kit-analysis/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-0835 — Microsoft 365

```text
https://logins-offcevents.icu
```

- **Domain:** `logins-offcevents.icu`
- **Technique:** AiTM reverse proxy (VoidProxy) behind fake corporate-event registration lure
- **Detection:** Block the whole .icu TLD if business-tolerable; otherwise alert on 'offce'/'offc' misspellings of office in new registrations
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0836 — Microsoft 365 / Entra ID

```text
https://accounts.logins-offcevents.icu
```

- **Domain:** `accounts.logins-offcevents.icu`
- **Technique:** VoidProxy AiTM Microsoft sign-in page harvesting credentials, MFA codes and session cookies
- **Detection:** Flag hostnames starting accounts.|login. on non-Microsoft apexes that serve a pixel-perfect Entra sign-in; watch for Entra sign-ins with a new device+ASN pairing minutes after the click
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0837 — Microsoft 365

```text
https://ydgjgdbhoa.shifts.icu
```

- **Domain:** `ydgjgdbhoa.shifts.icu`
- **Technique:** Kali365 device-code phishing backend (/api/generate) behind a fake Zoom/shift-portal lure
- **Detection:** Wildcard-block *.shifts.icu; random 10-char lowercase subdomain + /api/generate?lure= is the Kali365 fingerprint
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0838 — Microsoft 365

```text
https://nxinet.com
```

- **Domain:** `nxinet.com`
- **Technique:** MadApe phishing kit host serving a fake Microsoft sign-in page from PDF-attachment lures
- **Detection:** Hunt backend paths /api/code/entered and /api/code/status/<ID> in proxy logs — MadApe device-code kit signature
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0839 — Microsoft Teams

```text
https://lvborses.com
```

- **Domain:** `lvborses.com`
- **Technique:** MadApe kit; Microsoft Teams voicemail-notification lure leading to device-code sign-in
- **Detection:** Correlate 'Teams voicemail' emails with any click to a non-Microsoft host, then check Entra for devicecode-grant sign-ins
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0840 — Microsoft SharePoint

```text
https://secure-docs.liveoakfarmsllc.net
```

- **Domain:** `secure-docs.liveoakfarmsllc.net`
- **Technique:** MadApe kit; fake SharePoint document-share page funnelling to Microsoft device-code sign-in
- **Detection:** Flag 'secure-docs'/'securedocs' subdomains on unrelated apexes; alert on Entra authenticationProtocol=deviceCode
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0841 — Microsoft OneDrive

```text
https://durakdisplay.com
```

- **Domain:** `durakdisplay.com`
- **Technique:** MadApe kit; OneDrive-themed file-share lure to Microsoft device-code sign-in
- **Detection:** Block apex; hunt /api/code/status/ requests from user endpoints
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0842 — Microsoft 365

```text
https://securelogin.qimmxn.icu
```

- **Domain:** `securelogin.qimmxn.icu`
- **Technique:** MadApe redirect target presenting a fake 'secure login' step before Microsoft device-code entry
- **Detection:** Wildcard-block *.qimmxn.icu; 'securelogin.' label on a random .icu apex is a high-fidelity indicator
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0843 — Microsoft 365

```text
https://itencrypted.co
```

- **Domain:** `itencrypted.co`
- **Technique:** MadApe operator panel / kit control domain for Microsoft device-code campaigns
- **Detection:** Block apex; panel domains persist longer than phishing hosts, so they are the better blocklist anchor
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0844 — Microsoft 365

```text
https://householdwares.co
```

- **Domain:** `householdwares.co`
- **Technique:** MadApe operator panel domain (earliest sighting 2026-08-19)
- **Detection:** Block apex; hunt .co-TLD apexes with generic English compound names hosting /api/code/ paths
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0845 — Microsoft 365

```text
https://liva-fit.com
```

- **Domain:** `liva-fit.com`
- **Technique:** MadApe operator panel domain
- **Detection:** Block apex; pivot on shared TLS cert / hosting with itencrypted.co
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0846 — Microsoft 365

```text
https://uouso.net
```

- **Domain:** `uouso.net`
- **Technique:** MadApe operator panel domain
- **Detection:** Block apex; short random .net apexes with /api/code/entered endpoints
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0847 — Microsoft 365

```text
https://wbconnecticut.net
```

- **Domain:** `wbconnecticut.net`
- **Technique:** MadApe operator panel domain
- **Detection:** Block apex; geographic-sounding .net apexes reused as device-code kit panels
- **Source:** Aegis AI (on Group-IB research) — https://www.aegisai.com/threat-watch/madape-device-code-phishing-microsoft-365
- **Status:** active
- **First seen:** 2026-11-03

### mfs-0848 — Microsoft

```text
http://microsoft-winupdate.com/login
```

- **Domain:** `microsoft-winupdate.com`
- **Technique:** Fake 'Windows Update / Microsoft account' sign-in landing page on attacker-registered lookalike domain
- **Detection:** Alert on HTTP(S) to any non-Microsoft host containing 'microsoft' + ('winupdate'|'update') with a /login path; domain registered 2026-11-06
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0849 — Microsoft 365

```text
https://entry.richmondmarketingsystems.org
```

- **Domain:** `entry.richmondmarketingsystems.org`
- **Technique:** PhantomDOM browser-in-the-middle: entry host issues campaign JWT then hands off to DOM-mirroring auth subdomain
- **Detection:** Hunt for JWT-bearing redirects into *.richmondmarketingsystems.org; flag M365 logons whose referrer is a non-Microsoft host
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0850 — Microsoft 365

```text
https://5df1ab.richmondmarketingsystems.org
```

- **Domain:** `5df1ab.richmondmarketingsystems.org`
- **Technique:** Browser-in-the-middle DOM mirroring of login.microsoftonline.com behind Cloudflare Turnstile
- **Detection:** Flag DNS/proxy requests to 6-hex-character subdomains under a single registered domain — rotating BitM auth hosts
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0851 — Microsoft 365

```text
https://7c3206.richmondmarketingsystems.org
```

- **Domain:** `7c3206.richmondmarketingsystems.org`
- **Technique:** Rotating BitM authentication subdomain reconstructing the M365 sign-in DOM locally
- **Detection:** Block the parent domain rather than individual hosts; subdomains rotate per victim
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0852 — Microsoft 365

```text
https://fee349.richmondmarketingsystems.org
```

- **Domain:** `fee349.richmondmarketingsystems.org`
- **Technique:** Attacker-controlled BitM authentication host hijacking M365 sessions
- **Detection:** Correlate Entra ID sign-ins with sessions whose TLS SNI is not a Microsoft domain
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0853 — Microsoft 365

```text
https://28f4bc.richmondmarketingsystems.org
```

- **Domain:** `28f4bc.richmondmarketingsystems.org`
- **Technique:** Attacker-controlled BitM authentication host hijacking M365 sessions
- **Detection:** Wildcard-block *.richmondmarketingsystems.org in web filtering and tenant blocklists
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0854 — Microsoft 365

```text
https://exit.richmondmarketingsystems.org
```

- **Domain:** `exit.richmondmarketingsystems.org`
- **Technique:** Post-session exit host redirecting victims to a decoy DocuSign page after token theft
- **Detection:** A DocuSign redirect immediately following a non-Microsoft auth host is a strong post-compromise signal
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0855 — Microsoft 365

```text
https://richmondmarketingsystems.org
```

- **Domain:** `richmondmarketingsystems.org`
- **Technique:** Parent phishing infrastructure for the PhantomDOM BitM M365 kit
- **Detection:** Block at apex; registered solely to host the BitM M365 kit
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0856 — Microsoft 365

```text
https://pilotjobsnetwork.com
```

- **Domain:** `pilotjobsnetwork.com`
- **Technique:** Click-tracking redirector hop in the PhantomDOM M365 BitM chain (likely compromised site)
- **Detection:** Hunt email URLs resolving to this host followed within seconds by a 6-hex-subdomain auth request
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0857 — Microsoft 365

```text
https://nscoifas.com.br
```

- **Domain:** `nscoifas.com.br`
- **Technique:** First-stage anti-bot/fingerprinting gate in front of the PhantomDOM M365 sign-in page
- **Detection:** Flag .com.br hosts serving JS fingerprinting then redirecting to an M365-themed login
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0858 — Microsoft 365

```text
https://microsoftsonline.sbs
```

- **Domain:** `microsoftsonline.sbs`
- **Technique:** Typosquat of microsoftonline.com ('microsoftsonline') on cheap .sbs TLD
- **Detection:** Regex newly-registered domains for 'microsoft.?s?online' outside microsoft.com; block .sbs/.cfd/.pro cluster together
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0859 — Microsoft 365

```text
https://microsoftsonline.pro
```

- **Domain:** `microsoftsonline.pro`
- **Technique:** Typosquat of microsoftonline.com registered as part of a multi-TLD cluster
- **Detection:** Same registrant cluster as microsoftsonline.sbs/.cfd — pivot on WHOIS/NS to find siblings
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0860 — Microsoft 365

```text
https://microsoftsonline.cfd
```

- **Domain:** `microsoftsonline.cfd`
- **Technique:** Typosquat of microsoftonline.com on abuse-heavy .cfd TLD
- **Detection:** Block .cfd/.sbs/.shop/.top wholesale for Microsoft-brand lookalikes; near-zero legitimate use
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0861 — Microsoft 365

```text
https://m365online-microsoft.cam
```

- **Domain:** `m365online-microsoft.cam`
- **Technique:** Brand-concatenation squat ('m365online-microsoft') posing as the M365 portal
- **Detection:** Alert on any host combining 'm365' and 'microsoft' tokens on a non-Microsoft TLD
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0862 — Microsoft

```text
https://microsoft0.com
```

- **Domain:** `microsoft0.com`
- **Technique:** Digit-appended typosquat of microsoft.com used for account sign-in lures
- **Detection:** Hunt 'microsoft' + trailing digit domains in proxy logs and certificate transparency feeds
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0863 — Microsoft

```text
https://microsoftdesktop.com
```

- **Domain:** `microsoftdesktop.com`
- **Technique:** Brand-extension squat impersonating Microsoft desktop/account services
- **Detection:** Monitor CT logs for new certs on 'microsoft<word>.com' patterns not owned by Microsoft
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0864 — Microsoft Hotmail/Outlook

```text
https://mb-detailling84-hotmail.com
```

- **Domain:** `mb-detailling84-hotmail.com`
- **Technique:** Hotmail-suffixed lookalike domain mimicking a mailbox-owner address for credential capture
- **Detection:** Flag domains ending in '-hotmail.com' / '-outlook.com' — Microsoft never delegates these
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0865 — Microsoft

```text
https://microsoftindonesia.com
```

- **Domain:** `microsoftindonesia.com`
- **Technique:** Geo-themed brand squat ('Microsoft Indonesia') hosting regional sign-in lures
- **Detection:** Microsoft uses microsoft.com/id-id, never country-named apex domains — block the pattern
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0866 — Microsoft

```text
https://microsoftedge.homes
```

- **Domain:** `microsoftedge.homes`
- **Technique:** Edge-branded squat on .homes TLD used for update/sign-in prompts
- **Detection:** Alert on 'microsoftedge' outside microsoft.com; .homes has no legitimate Microsoft presence
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0867 — Microsoft Outlook

```text
https://rnicrosoft-outlook.com
```

- **Domain:** `rnicrosoft-outlook.com`
- **Technique:** Homoglyph typosquat substituting 'rn' for 'm' in 'microsoft'
- **Detection:** Run a confusables/IDN-skeleton check for 'rn'→'m' and 'vv'→'w' against microsoft brand terms
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0868 — Microsoft Outlook

```text
https://microsft-outlook.com
```

- **Domain:** `microsft-outlook.com`
- **Technique:** Character-omission typosquat ('microsft') for Outlook webmail credential theft
- **Detection:** Levenshtein distance ≤2 from 'microsoft' on newly registered domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0869 — Microsoft 365

```text
https://microsoft365-login.online
```

- **Domain:** `microsoft365-login.online`
- **Technique:** Explicit 'microsoft365-login' credential-harvest domain on .online TLD
- **Detection:** High-confidence block: brand + 'login' keyword on non-Microsoft TLD
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0870 — Microsoft 365

```text
https://microsoft-auth365.com
```

- **Domain:** `microsoft-auth365.com`
- **Technique:** Fake Microsoft 365 authentication endpoint domain
- **Detection:** Flag hostnames pairing 'microsoft'/'365' with 'auth', 'sso', or 'oauth' outside Microsoft namespaces
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0871 — Microsoft Outlook

```text
https://outlookshield.com
```

- **Domain:** `outlookshield.com`
- **Technique:** Security-themed Outlook squat ('shield') for mailbox-protection sign-in lures
- **Detection:** Hunt Outlook/Microsoft brand terms combined with 'shield', 'protect', 'secure', 'defend'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0872 — Microsoft Outlook

```text
https://outlookshield.site
```

- **Domain:** `outlookshield.site`
- **Technique:** Security-themed Outlook squat on .site TLD, sibling of outlookshield.com
- **Detection:** Block both TLD variants; registered same day as outlookshield.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0873 — Microsoft Outlook

```text
https://outlooklab.app
```

- **Domain:** `outlooklab.app`
- **Technique:** Outlook brand squat on .app TLD presenting a webmail sign-in form
- **Detection:** Alert on 'outlook' in hostnames on .app/.dev — HSTS-preloaded TLDs favored for clean TLS
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0874 — Microsoft OneDrive

```text
https://open-onedrive.online
```

- **Domain:** `open-onedrive.online`
- **Technique:** OneDrive 'open document' lure domain fronting a Microsoft sign-in prompt
- **Detection:** Flag 'onedrive' + verb prefixes (open-, view-, shared-) on non-Microsoft domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0875 — Microsoft OneDrive

```text
https://onedrivehelp.com
```

- **Domain:** `onedrivehelp.com`
- **Technique:** Fake OneDrive support/help portal harvesting Microsoft account credentials
- **Detection:** Hunt 'onedrive' + ('help'|'support'|'desk') outside microsoft.com/support
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0876 — Microsoft Hotmail

```text
https://hotmail.ceo
```

- **Domain:** `hotmail.ceo`
- **Technique:** Exact brand name on an unrelated vanity TLD (.ceo) for webmail credential capture
- **Detection:** Block exact Microsoft brand labels ('hotmail','outlook','msn') on any TLD Microsoft does not own
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0877 — Microsoft 365

```text
https://xn--microsoftonine-5kc.com
```

- **Domain:** `xn--microsoftonine-5kc.com`
- **Technique:** IDN homoglyph attack — punycode domain rendering as a Unicode 'microsoftonline' lookalike
- **Detection:** Alert on any xn-- domain whose Unicode skeleton matches a Microsoft brand term; browsers may render it natively
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0878 — Microsoft 365

```text
https://microsoft-onl1ne.com
```

- **Domain:** `microsoft-onl1ne.com`
- **Technique:** Digit-for-letter typosquat of microsoftonline.com (1 for i)
- **Detection:** Normalize 1→i, 0→o, 5→s before matching hostnames against the Microsoft brand list
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0879 — Microsoft

```text
https://micros0ftauth.com
```

- **Domain:** `micros0ftauth.com`
- **Technique:** Digit-substitution typosquat ('micros0ft') on a fake auth endpoint
- **Detection:** Same leet-normalization rule; pair with 'auth' keyword for high-confidence blocking
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0880 — Microsoft 365

```text
https://microsoft-login.online
```

- **Domain:** `microsoft-login.online`
- **Technique:** Generic 'microsoft-login' credential-harvest domain on .online TLD
- **Detection:** High-confidence block: brand + 'login' on non-Microsoft TLD
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0881 — Microsoft 365 / Defender

```text
https://office365defender.com
```

- **Domain:** `office365defender.com`
- **Technique:** Defender-themed security-alert lure domain leading to an Office 365 sign-in page
- **Detection:** Hunt 'defender' combined with 'office365'/'microsoft' outside security.microsoft.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0882 — Microsoft

```text
https://microsoftsupport.fun
```

- **Domain:** `microsoftsupport.fun`
- **Technique:** Fake Microsoft support portal on .fun TLD used for account-verification sign-in lures
- **Detection:** Block 'microsoftsupport' on any TLD; Microsoft support lives only on microsoft.com/support
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0883 — Microsoft Live/Hotmail

```text
https://your-hotmail-live.com
```

- **Domain:** `your-hotmail-live.com`
- **Technique:** Possessive-prefix squat ('your-hotmail-live') impersonating Microsoft Live sign-in
- **Detection:** Flag 'hotmail' or 'live' with hyphenated prefixes (your-, my-, secure-) on non-Microsoft apexes
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-07

### mfs-0884 — Microsoft OneDrive/Azure

```text
https://storage-microsoft-ewc.shop
```

- **Domain:** `storage-microsoft-ewc.shop`
- **Technique:** Fake Microsoft storage/quota warning domain on .shop TLD
- **Detection:** Alert on 'microsoft' on .shop/.store TLDs; combine with 'storage'/'quota' keywords
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-06

### mfs-0885 — Microsoft

```text
https://shield-microsoft.com
```

- **Domain:** `shield-microsoft.com`
- **Technique:** Security-themed brand squat ('shield-microsoft') for account-protection sign-in lures
- **Detection:** Hunt hyphenated 'microsoft' compounds with security verbs; check cert issuance date <30 days
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-06

### mfs-0886 — Microsoft Outlook

```text
https://outlooks.page
```

- **Domain:** `outlooks.page`
- **Technique:** Pluralized Outlook squat on .page TLD serving a webmail sign-in form
- **Detection:** Flag 'outlooks'/'outlook' labels on .page/.app; Microsoft owns neither
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-06

### mfs-0887 — Microsoft Outlook

```text
https://outlook-kwwoerden.one
```

- **Domain:** `outlook-kwwoerden.one`
- **Technique:** Targeted squat embedding a victim-organization token after 'outlook-' for a tailored sign-in lure
- **Detection:** Alert on 'outlook-<orgname>' patterns — a strong indicator of org-specific credential phishing
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-06

### mfs-0888 — Microsoft Hotmail

```text
https://hotmaililil.shop
```

- **Domain:** `hotmaililil.shop`
- **Technique:** Character-padded Hotmail typosquat ('hotmaililil') on .shop TLD
- **Detection:** Fuzzy-match 'hotmail' with repeated-character insertions; part of a recurring hotmail*.shop cluster
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-06

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["n2cknem.github.io", "outlook-login.github.io", "office365.internal-alerts.com", "support.m365-microsoft.com", "programme-hup.m365-microsoft.com", "emailnotifications.m365-microsoft.com", "office365.rricrosoft-offices.org", "security.email-microsoft.com", "auth.properties", "outlook.webaccess-alert.com", "outlook.verifytoken.com", "onedrive.at-us.therelayservice.com", "81.190.202.64.host.secureserver.net", "www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "reactivar-microsoft-live.iceiy.com", "outlook-email-2026.hstn.me", "0365-microsoft.gitbook.io", "401283-outlookmailbox-00012-validate.weebly.com", "microsoft.citrix-sharing.com", "plugins.sugar-outlook.com", "microsoft-sharepoint.fr", "microsoft365updates.com", "microsoft365businessbasic.com", "office365licensingsupport.com", "csp.microsoftsupportcenter.digital", "microsoft-se.us", "microsoftuk.co", "microsoftpl.biz.pl", "microsoftjk.eu.org", "microsoft.updata.net.cn", "outlookmail.social", "office.rox-klimatechnik.sbs", "mslogin.oauth-live.com", "login.oauth-live.com", "teams-cloud.live", "amgen.teams-cloud.live", "abcgil.com", "dayoadeyemo.com", "f005.backblazeb2.com", "spazioaperto-shared-document.live-document-mcs365980.workers.dev", "www.safe365apps.com", "www.safe365apps.com", "security.m365-microsoft.com", "outlook365livee.dothome.co.kr", "v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site", "mail.v3sec.microsoftonline-com-common-signin-openid.129-121-112-148.cpanel.site", "www.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "ttgyahvw.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "www.zygzsdwh.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "www.mxjkckus.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "orygozcb.login.microsoftonline-billing-verification-secured-help.104-248-114-136.cpanel.site", "microsoftcloudverification.com", "sso.microsoft-onedrive.org", "outlookmails.de", "mail.outlookmails.de", "outlook-silk-nine.vercel.app", "outlook-ashy.vercel.app", "m365-microsoft.com", "microsoft-africa.org", "cocoonwoodsavoie.com", "f005.backblazeb2.com", "microsoftconfig-3.vercel.app", "outlook-phi-one.vercel.app", "grn-microsoft-outlook.vercel.app", "msauth.biz", "dv0psh-purv3w-azfn-b2c0-msauth3-m365svc-s3ntln-4zrfn3x-cntnrx.workers.dev", "ssosvc-m365s-kvl-dv0pshb-s3ntln-c0mply-4zrmonx-apimgwx-evnthb.workers.dev", "wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev", "purv3w3-t3ms4pp-certs-intun3-sbussvx-4zredg-siemsv-pip3ln-0ffc3.workers.dev", "c5id-pc17-fffoub1-bul3-ahv1-r00kubt.ondrv-pwrbi3-s3ntln-quesvxs-l0gsvx-entr-m365s-cmplncx-ehubn.workers.dev", "d3m9a-goo2ns-wx0g-jzhuc2-t9r2b9i.dvps-azbl-fnapp-trc3svc-synpx-quesvxs-purv3-siemsvx-cmplncx.workers.dev", "unhf69e-e0ppo-l0qoo-a12bcfj-ig1sa4v.wndws-pip3ln-sql3-waf3-purv3-gdprsx-dfn-azfn-appsvc-0ffapx.workers.dev", "fgwhjmdaurspxvznk.hutspotmaken.eu", "sites.google.com", "sites.google.com", "creyt.cl", "sharepointonline-microsoft.com", "www.microsofl.compras-ok.com", "microsoftoutlook.flazio.online", "microsoft0117.vercel.app", "onedrive-1-one.vercel.app", "wahat-ipp.sa-onedrive.com", "validar-micuenta-outlook.yzz.me", "microsoft-online.gr", "microsoft-telemetry.at", "outlook.us.org", "beacon-surge-sync.workers.dev", "miicro67soft.vercel.app", "oosoftlms.weebly.com", "knkddkmlmeaedd.weebly.com", "security-server-website--danlelbacker.replit.app", "admin-suport-update-com.weebly.com", "help.microsofth.com", "auth.microsofth.com", "apps.microsofth.com", "azure.microsofth.com", "cloud.microsofth.com", "com.microsofth.com", "data.microsofth.com", "dotnet.microsofth.com", "edge.microsofth.com", "flow.microsofth.com", "security-server-page--michaelfrank112.replit.app", "kalgaaaaa.webflow.io", "biesse.en-onedrive.com", "aiapp2.outlook1.cc", "sdc.bcn.mybluehost.me", "sdc.bcn.mybluehost.me", "global-fuchsia-9par6vcz-dp5x4caf1rmk.edgeone.dev", "microfis-password-recovery.wasmer.app", "doc-portail-groupegouletsports.vercel.app", "plusone.google.com", "shohag.shop", "fls-a2a307fb-f2fd-4664-8c1e-e855892944cf.laravel.cloud", "achermanrmalerch.click", "fairsealines.com", "leanl-rosy.vercel.app", "arasyaplastic.com", "www.sharepoint-notification.vercel.app", "pay.myoffice365.ninja", "office365login-1f9d1.web.app", "office365-ff2ac.firebaseapp.com", "owa-mail-auth.firebaseapp.com", "officeadmin2026.weebly.com", "microsoftoniine.my", "outlook.accountantsclaim.com", "login-microsoftonline.pl", "www.microsoft-office365.site", "micronosoft.com", "emergingoutlookreport.com", "microsoftt7.vercel.app", "teams.microsoftonline-sharepoint.online", "microsoftturkey.com", "microsoftturkiye.com", "projectshare.ngrok.pro", "www.sharepoint-eight-alpha.vercel.app", "owalotte.net", "aminsheikh72.github.io", "office365-ff2ac.web.app", "outlooksa.vercel.app", "sharepnt.ngrok.pro", "api.hotmail666.com", "usdt.hotmail666.com", "microsoft.o356.ee", "outlook-mailer.com", "login.microsoftofice.cz", "login.microsoftofice.cz", "authenticate-microsoftonline.com", "auth-microsoft.app", "microsoftoine.com", "microsoft-support-center.com", "microsoft365api.com", "microsoftup.top", "outlook-verify-session.top", "outlookmailbox.com", "microsoftsupport.digital", "care-microsoft.com", "hotmaill.live", "outlook-verif.com", "onedrivedocs.xn--q9jyb4c", "office365online.com", "outlookts.com", "saferlink-outlook.com", "microsoftoffice365.top", "onedrives-msa-document-access.online", "onedrive-sync.top", "updtes-microsoft.com", "microsofty-security.com", "defend-microsoft.com", "folder-onedrive-live.com", "accounts-outlook.com", "accountprotection-microsofts.click", "accountprotection-microsofts.website", "accountprotection-microsofts.store", "accountprotection-microsofts.sbs", "accountprotection-microsofts.monster", "accountprotection-microsofts.cyou", "accountprotection-microsofts.buzz", "notification-outlook.com", "off365acess.jumpingcrab.com", "torvion.life", "priorispace.biz", "5200m.com", "ghethim.com", "flow505.mooo.com", "bigbrain.chickenkiller.com", "outlook40394343.web.app", "outlook40394343.firebaseapp.com", "sharepoint.onedrive.dczhxkw84930320.passkey.auth02.outlook.drive.plastkon.cc", "verificarcuenta-micros0ft2026way.zya.me", "goldcreekconcrete.com", "goldcreekconcrete.org", "openai.eventrsvp.app", "spacex.eventrsvp.app", "anthropic.rsvpconnect-events.com", "register.rsvpconnect-events.com", "62zr4vcasl.shifts.icu", "continue-to-office-.ggleventapi.icu", "login.wbdssologin.app", "wbdssologin.app", "nextconfirmationlogin.officegocrqb.com", "continueevenregistration.officegocrqb.com", "continuessoevent.officegocrqb.com", "signincomplete.offcevent-login.com", "offcevent-login.com", "office.com-access-sharepoint.com", "eventrsvp-217-60-102-48.sslip.io", "splace.co.za", "sdocshares.auth.outlook2026common.copilos26.csr-rooflng.com", "pdocshared.payments2026.outlooks.common.ecmholdlnggroup.com", "login.microsoftofice.cz", "microsoftontine.com", "microsoftonilne-na.com", "login--microsoftonline.com", "microsoft365emailessentials.online", "hotmaill.shop", "cdn-microsoft.top", "outlook-s.com", "rustic-outlook.com", "notes-to-outlook.com", "outlookmailgmail.com", "outlookcentertop.biz", "outlook366.com", "outlooktracker.com", "outlook-info.com", "review-outlook.com", "onedriverdocument.com", "onedrivedisk.com", "onedrivea.net", "microsoftsetup.com", "microsofts.network", "microsoftupdate.site", "microsoftupdate.pro", "microsoft-update.surf", "microsoft365essential.com", "microsoft365-download-office.com", "microsoft365s.com", "microsofttl.com", "office365store.com", "partner-office365.org", "tickets-microsoft.com", "hotmailsistermail.com", "auth.login.office365.cloud.onedrive.outlook.atlarchitacts.com", "authorize.copilot.outlook.common.microsoft0365.atlarchitacts.com", "copilot.login.office365outlook.cloud.onedrive.atlarchitacts.com", "reauth.copilot.common.outlook.mcloud365.atlarchitacts.com", "awemode.outlookoffice365.microsoftcopilots.docshare.linnwest.us", "copilots.outlook.cloud.microsoft.andersonelevators.com", "copilots.outlook.cloud.microsoft.syrosconstructlon.com", "statement.docdriveoauth.authorized.copilot.syrosconstructlon.com", "docshare.auth.copilot.outlook.onedrive.common.earthlink-net.com", "docshare.auth.copilot.outlook.onedrive.common.evergreenerg.com", "docshare.auth.copilot.outlook.onedrive.common0.evergreenerg.com", "docshare.auth.copilot.outlook.onedrive.common.northemheating.com", "docshare.auth.copilot.outlookonedrive.common.northemheating.com", "docshare.auth2026.onedrive.outlooksdocument.csr-rooflng.com", "docshares.auth2026.outlookcommon.copilots.commm.csr-rooflng.com", "sdocshares.auth.outlook.copilos26.general.csr-rooflng.com", "sdocshares.authoutlooks.common.copilots2026.hathormson.com", "pdocshared.documents2026.docs.shared.ecmholdlnggroup.com", "efaxdoc.auth.login.outlook.office365.tescoccontrols.com", "efaxdoc.auth.outlook2026common.copilos26.bettylnc.com", "payapp.auth.outlook2026common.copilos26.bettylnc.com", "efaxdoc.auth.outlook2026common.copilos26.ikextal-co-kr.com", "pdfdocshared.auth.outlook2026common.copilos26.ikextal-co-kr.com", "efaxdoc.auth.outlook2026common.copilos26.kone-inc.com", "efaxdoc.documents2026.cmc.docs.shared.matchlinemechanicallc.com", "efaxdoc.documents2026.docs.shared.lakeviewscustom.com", "ecosys.newdocument2026.pdfdocshared.tntileandmarbleinc.com", "login.microsoft365.outlook.copilotsoffice365.lntactpr.com", "login.office365outlooks.microsoft.cloud-outlook.naregruop.com", "naregruop.com", "m365cloud.login.outlook.office365.azgymfloor.com", "azgymfloor.com", "outlookdrive.microsoftonline.common.oauth2.client.buycerm.com", "reauth.copilot.auth.outlook.mcloud365.buycerm.com", "reauth.copilot.auth.outlook.mcloud365.myhalnc.com", "reauth.docs.copilot.auth02.outlook.mcloud365.argentventuras.com", "outlookoffice365.microsoftcopilots.vigilantlnc.com", "statement.outlookoffice365.microsoftcopilots.calmechc.net", "calmechc.net", "statements.outlook.office365microsoft.payment.run.stoneclty.com", "shared.paymentsclouds.statementsapproved.jetbusinesscapltal.com", "wsochares.authpayments.common.paid2026.bullochdirtwroks.com", "sedocs.docs.payrol2026.common.copilots2026.vatrarnsformer.com", "0ff365access.mooo.com", "bennett002.mooo.com", "0utlook0ffice365admin.twilightparadox.com", "office0365login.2waky.com", "off365mail.club", "flow55.chickenkiller.com", "swiftii.chickenkiller.com", "kilishy.qhigh.com", "linking.mefound.com", "gregor.justdied.com", "atlantictriad.ignorelist.com", "auth-loadingdocuments.online", "eccentric-authentication.com", "logins-offcevents.icu", "accounts.logins-offcevents.icu", "ydgjgdbhoa.shifts.icu", "nxinet.com", "lvborses.com", "secure-docs.liveoakfarmsllc.net", "durakdisplay.com", "securelogin.qimmxn.icu", "itencrypted.co", "householdwares.co", "liva-fit.com", "uouso.net", "wbconnecticut.net", "microsoft-winupdate.com", "entry.richmondmarketingsystems.org", "5df1ab.richmondmarketingsystems.org", "7c3206.richmondmarketingsystems.org", "fee349.richmondmarketingsystems.org", "28f4bc.richmondmarketingsystems.org", "exit.richmondmarketingsystems.org", "richmondmarketingsystems.org", "pilotjobsnetwork.com", "nscoifas.com.br", "microsoftsonline.sbs", "microsoftsonline.pro", "microsoftsonline.cfd", "m365online-microsoft.cam", "microsoft0.com", "microsoftdesktop.com", "mb-detailling84-hotmail.com", "microsoftindonesia.com", "microsoftedge.homes", "rnicrosoft-outlook.com", "microsft-outlook.com", "microsoft365-login.online", "microsoft-auth365.com", "outlookshield.com", "outlookshield.site", "outlooklab.app", "open-onedrive.online", "onedrivehelp.com", "hotmail.ceo", "xn--microsoftonine-5kc.com", "microsoft-onl1ne.com", "micros0ftauth.com", "microsoft-login.online", "office365defender.com", "microsoftsupport.fun", "your-hotmail-live.com", "storage-microsoft-ewc.shop", "shield-microsoft.com", "outlooks.page", "outlook-kwwoerden.one", "hotmaililil.shop"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

