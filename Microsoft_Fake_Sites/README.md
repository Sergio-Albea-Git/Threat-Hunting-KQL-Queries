# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 170
- **Retention:** rolling 30 days
- **Last updated:** 2026-10-20
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
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
| mfs-0368 | Microsoft account / Outlook | Fake 'Security verification - Microsoft account' credential-harvest page on a free Replit app subdomain (security-server-page-- template) | 2026-09-22 | OpenPhish |
| mfs-0369 | Microsoft account / Outlook | Same Replit 'security-server-landing-page--' Microsoft account verification template seen in earlier replit.app lures | 2026-09-22 | OpenPhish |
| mfs-0397 | Outlook / Exchange | Compromised site hosting a fake Exchange/Outlook portal | 2026-09-21 | OpenPhish (via urlscan.io) |
| mfs-0401 | Microsoft OneDrive | Chain of Cloudflare Workers redirects ending on a fake OneDrive page | 2026-09-21 | OpenPhish (via urlscan.io) |
| mfs-0417 | Microsoft account | Same /E.<token> infrastructure as authentication.ms and multi-factor.link; a sibling URL decodes to a Hoxhunt simulation string, so this may be training infrastructure | 2026-09-22 | OpenPhish (via urlscan.io) |
| mfs-0418 | Microsoft account (E.ON lure) | /E.<token> kit on an E.ON-lookalike domain; possibly phishing-simulation infrastructure | 2026-09-21 | OpenPhish (via urlscan.io) |
| mfs-0419 | Microsoft SharePoint | Typosquat domain ae-sharepoint.com with per-target company subdomains ('Sharepoint Secure Panel'), 0 days old | 2026-09-22 | urlscan.io certstream-suspicious |
| mfs-0420 | Microsoft SharePoint | Per-target subdomain that redirects to sharepointdocument-verification.com ('SharePoint — Documents') | 2026-09-22 | urlscan.io certstream-suspicious |
| mfs-0421 | Microsoft 365 | 0-day-old domain serving a cloned Entra ID 'Sign in to your account' page at /auth | 2026-09-21 | urlscan.io |
| mfs-0422 | Microsoft 365 | 0-day-old typo domain ('gruop') hosting a Microsoft sign-in clone | 2026-09-21 | urlscan.io |
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

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["connectezvousamicrosoftoutlook.weebly.com", "auth.properties", "multi-factor.link", "multi-factor.link", "authentication.ms", "m365-online.ch", "moripartnerch-365-mso-drive-auth9287364.cloud-storage-id0384723.workers.dev", "xn--knto-55d.evergreenfin.ltd", "s.teams-ra.com", "adi-panwar.github.io", "nk2184.craftum.io", "security-server-page--emekemine206.replit.app", "security-server-landing-page--mariodrichard.replit.app", "timeforgoldens.com", "divine-sea-8f82.jernzen26.workers.dev", "signin.broker", "gsd.eon-account.com", "almaghrabifactory-com.ae-sharepoint.com", "unisusgroups.ae-sharepoint.com", "vendnue.com", "koukgruop.com", "f005.backblazeb2.com", "microsoft-0r.github.io", "owa.goldensemolina.com.tr", "security-server-landing-page--james2606.replit.app", "cgi.s-ed1.cloud.gcore.lu", "s.teams-tb.com", "teams-lo.com", "www.the365notify.com", "security-server-landing-page--peterajiri2000.replit.app", "scsproyectos.cl", "pizzlelinchy.s3.us-east-1.amazonaws.com", "hotmail365new.s3.ap-northeast-1.amazonaws.com", "f005.backblazeb2.com", "accounts-ba666e1a.jkhjkjk.workers.dev", "wildlands.acltci.com", "validar-micuenta-outlook.yzz.me", "authentication.ms", "publicofficeoutlooknotificationscry-dpkjhfszqaa2.edgeone.dev", "security-server-page--sheryln1990.replit.app", "security-server--tabbielynn.replit.app", "security-server-page--servarog.replit.app", "microsoft0117.vercel.app", "creyt.cl", "clovdmicrsotfmailaamkagmxn2uxywe.klassik-erh.de", "microsoft-online.gr", "microsoftoffice-o365.com", "www.miccrossofteam.top", "www.connexioncompteoutlook.weebly.com", "verificarcuenta-micros0ft2026way.zya.me", "microsoft-office365.site", "microsoftsteam.live", "forms-microsoft.com", "microsofteams-setup.com", "login-microsoft-verify.online", "microsoft-account.live", "microsoft-key.online", "office365plus.net", "microsofteamsinvite.top", "hotmailli.site", "outlookinboxmessage.com", "microsofteamsinvite.live", "teams-microsofts-meet.com", "teams-microsoft-downloads.com", "outlook.surf", "onedriveshare.net", "onedrivecloud.net", "microsoft-windows-support.com", "microsoft-onedrive.org", "inbox-microsoft.com", "0nedrive.space", "salessupport-microsoft.com", "protect-outlook.com", "outlookaccessportal.com", "com-onedrive.com", "accountrecovery-outlook.com", "m365-login-microsoft.com", "microsoft-security.online", "onedrive-mysharepoint.com", "mylogin-microsoftonline.com", "ms365-onedrive.com", "accounts-login-micr0s0ft-mailsetup.com", "myaccount-microsoft365.com", "outlook.evergreenfin.ltd", "micr0s0ft0ffice365.com", "microsoftonlinesm.top", "com-microsoft-onedrive.live", "outlookk.site", "outlook-email-primecaretech.com", "microsoftfile.xyz", "microsoftpro.top", "microsoftplus.com", "microsoftolnine.com", "microsoftentraconnect.com", "microsoftteamupdate.com", "microsoftofficeph.com", "0nedrive.online", "microsoftidonline.com", "microsoftprovider.com", "microsoftfileoffline.top", "outlook.day", "microsoftonedrivesync.top", "fra-microsoft.com", "fra-microsoft.info", "fra-microsoft.store", "axisurbanmobilityllc-outlook-company.com", "outlook.beer", "outlook.baby", "urgent-microsoft.com", "teams-microsoft.cloud", "microsoftteamssviewer.com", "outlookwebupdate.com", "microsoft-messaging.com", "microsoft08619.com", "onmicrosoftonline-mmscrmcustomers.mm.am", "site.com-microsoftonline-ondrive.ca", "notifications.microsoft-ssl.com", "click2.microsoftsupportcenter.digital", "login-outlook365.yzz.me", "microsoft-alpha.vercel.app", "outlook-serv-coral.vercel.app", "onedrive-4-nine.vercel.app", "www.onedrive-4-nine.vercel.app", "network-office-cm51.bolt.host", "namastespa.ca", "microsoftwordob.blogspot.com", "n2cknem.github.io", "outlook-login.github.io", "office365.internal-alerts.com", "support.m365-microsoft.com", "programme-hup.m365-microsoft.com", "emailnotifications.m365-microsoft.com", "office365.rricrosoft-offices.org", "security.email-microsoft.com", "auth.properties", "outlook.webaccess-alert.com", "outlook.verifytoken.com", "onedrive.at-us.therelayservice.com", "81.190.202.64.host.secureserver.net", "www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "reactivar-microsoft-live.iceiy.com", "outlook-email-2026.hstn.me", "0365-microsoft.gitbook.io", "401283-outlookmailbox-00012-validate.weebly.com", "microsoft.citrix-sharing.com", "plugins.sugar-outlook.com", "microsoft-sharepoint.fr", "microsoft365updates.com", "microsoft365businessbasic.com", "office365licensingsupport.com", "csp.microsoftsupportcenter.digital", "microsoft-se.us", "microsoftuk.co", "microsoftpl.biz.pl", "microsoftjk.eu.org", "microsoft.updata.net.cn", "outlookmail.social", "office.rox-klimatechnik.sbs", "mslogin.oauth-live.com", "login.oauth-live.com", "teams-cloud.live", "amgen.teams-cloud.live", "abcgil.com", "dayoadeyemo.com", "f005.backblazeb2.com", "spazioaperto-shared-document.live-document-mcs365980.workers.dev", "www.safe365apps.com", "www.safe365apps.com", "security.m365-microsoft.com", "outlook365livee.dothome.co.kr"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

