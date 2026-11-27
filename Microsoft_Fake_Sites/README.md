# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** The URLs below are **LIVE, real, un-defanged** phishing
> URLs that impersonate Microsoft sign-in pages, published as a **blocklist / detection**
> feed (like URLhaus / OpenPhish). **Do not visit them or submit credentials.** Consume
> them in proxy/DNS/mail blocks and hunting queries — not in a browser.

This catalog tracks URLs that impersonate Microsoft sign-in (Microsoft 365, Office, Outlook,
Azure AD / **Entra ID**, Live). It is refreshed **hourly** by an automated tracker that
web-searches public phishing feeds and vendor reporting, and it keeps a **rolling 30-day**
window — entries older than that are dropped automatically.

- **Entries:** 502
- **Retention:** rolling 30 days
- **Last updated:** 2026-11-27
- **Maintained by:** PAI Microsoft Fake Sites Tracker (hourly) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Sites

| ID | Brand | Technique | First seen | Source |
| --- | --- | --- | --- | --- |
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
| mfs-0723 | Microsoft Outlook | Credential-harvesting fake Outlook sign-in hosted on Firebase/Google web.app free hosting (page title 'Sample Background') | 2026-11-01 | PhishDestroy |
| mfs-0724 | Microsoft Outlook | Same kit as the .web.app twin — Firebase-hosted fake Outlook login; firebaseapp.com is the paired default domain for the same Firebase project | 2026-11-01 | PhishDestroy |
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
| mfs-0889 | Microsoft Teams | Compromised legitimate site hosting a Teams "scheduled meeting" lure path that chains to an M365 credential form | 2026-11-10 | TweetFeed (via phishunt.io) |
| mfs-0890 | Office 365 | Free-hosting (Weebly) fake document gate — "Sign in With Your Office 365 Email To Review PDF Document" | 2026-11-09 | PhishDestroy |
| mfs-0891 | Microsoft Excel / Microsoft 365 | Weebly-hosted Excel-branded "Sign in to view the document" credential form | 2026-11-09 | PhishDestroy |
| mfs-0892 | Microsoft 365 | Vercel-hosted clone of the ConvergedSignIn page ("Email, phone, or Skype" field, Next button) | 2026-11-08 | PhishDestroy |
| mfs-0893 | Microsoft 365 | Spanish-language ("Iniciar sesión") Microsoft sign-in clone on Vercel with custom background art | 2026-11-08 | PhishDestroy |
| mfs-0894 | Microsoft 365 | www redirector feeding the ucsg365.vercel.app Microsoft sign-in clone | 2026-11-08 | PhishDestroy |
| mfs-0895 | Microsoft SharePoint | GitHub Pages SharePoint-branded loader page pulling real aadcdn.msauth.net / logincdn.msauth.net assets to look authentic | 2026-11-01 | PhishDestroy |
| mfs-0896 | Outlook Web App (OWA) | Firebase Hosting OWA kit — HTML title 'Outlook' with cloaked/blank body served to scanners | 2026-11-01 | PhishDestroy |
| mfs-0897 | Microsoft OneDrive | Credential-harvesting fake OneDrive/Microsoft sign-in page hosted on free Vercel subdomain | 2026-11-10 | phishunt.io (Microsoft tracker, updated hourly) |
| mfs-0899 | Microsoft 365 / OneDrive | Typosquat using 'com-microsoftonline-ondrive' as a registrable label to fake a Microsoft hostname chain | 2026-11-10 | phishunt.io (Microsoft tracker) |
| mfs-0905 | Microsoft | German-language fake Microsoft 'Anmelden' sign-in card behind a 308 redirect, Hetzner-hosted (46.225.73.32) | 2026-11-08 | PhishDestroy |
| mfs-0907 | Microsoft 365 (via fake AI/aerospace event lures) | Kali365 device-code phishing + VoidProxy AiTM apex lure domain (fake OpenAI/SpaceX event RSVP) | 2026-11-05 | Push Security |
| mfs-0908 | Microsoft 365 (via fake Anthropic event lure) | Apex lure domain fronting Kali365 device-code and VoidProxy reverse-proxy sign-in pages | 2026-11-05 | Push Security |
| mfs-0910 | Microsoft | Newly registered sign-in-themed lookalike domain on abused .sbs TLD | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0911 | Microsoft Hotmail / Outlook | Newly registered Hotmail brand-lookalike domain staged for credential harvesting | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0912 | Microsoft Outlook | Newly registered 'mail security' themed Outlook lookalike (classic mailbox-quota/secure-message lure pattern) | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0913 | Microsoft Office 365 | Newly registered Office 365 brand-lookalike domain | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0914 | Microsoft Office 365 | Newly registered Office 365 brand-lookalike domain | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0915 | Microsoft | Newly registered password-reset themed Microsoft lookalike | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0916 | Microsoft / Outlook mail | Newly registered Microsoft mail-themed lookalike domain | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0917 | Microsoft OneDrive / SharePoint | Newly registered file-share themed lookalike for shared-document sign-in lures | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0918 | Microsoft | Newly registered random-suffix Microsoft lookalike (bulk-registration pattern) | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0919 | Microsoft 365 | Newly registered exact brand match on a low-reputation TLD | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0920 | Microsoft | Newly registered Microsoft brand-lookalike domain (licensing/reseller lure theme) | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0921 | Microsoft Outlook | Newly registered compound-word Outlook lookalike on .app TLD | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0922 | Microsoft | Newly registered infrastructure-themed Microsoft lookalike (fake CDN/storage host for phish assets) | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0923 | Microsoft | Newly registered fake-CDN lookalike used to host phishing kit resources and exfil endpoints | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0924 | Microsoft Entra ID / Azure AD | Newly registered login-prefixed lookalike mimicking Microsoft's auth hostname | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0925 | Microsoft SharePoint Online | Newly registered SharePoint/microsoftonline hybrid lookalike for shared-file sign-in lures | 2026-11-10 | phishunt.io newly-registered Microsoft domains |
| mfs-0926 | Microsoft Outlook/Hotmail | Credential-harvest clone of Hotmail/Outlook sign-in hosted on free Vercel subdomain | 2026-11-11 | OpenPhish via phishunt.io |
| mfs-0927 | Microsoft 365 | Compromised legitimate site hosting fake M365 /login page with signin/secure query params | 2026-11-11 | OpenPhish via phishunt.io |
| mfs-0928 | Microsoft 365 / Teams | Device-code phishing — typosquatted domain + Google share-link redirect chain hides a Teams meeting-booking lure that relays a real Microsoft device code | 2026-11-12 | Huntress |
| mfs-0933 | Microsoft SharePoint / Microsoft 365 | Typosquat apex combining microsoftonline + sharepoint on the .online TLD, fronting a fake SharePoint document-share sign-in | 2026-11-02 | phishunt.io feed |
| mfs-0953 | Microsoft 365 / SharePoint | Compromised sender domain delivering SharePoint-themed PDF lures into the PhantomDOM Browser-in-the-Middle session-hijack chain | 2026-11-05 | ZeroBEC |
| mfs-0954 | Microsoft Outlook / Office 365 | Credential-harvest page hosted on GitHub Pages ('paneldecontrol-365' Spanish-language Outlook panel lure) | 2026-11-15 | OpenPhish / Google Safe Browsing (via phishunt) |
| mfs-0955 | Microsoft 365 | Targeted subdomain-per-victim phishing (victim org name prefixed to attacker-owned 'microsoft-alerts' domain) | 2026-11-14 | Google Safe Browsing (via phishunt) |
| mfs-0956 | Microsoft 365 / Exchange Online | Final credential-harvest landing for the Nov 12 M365 outage 'held messages will be deleted in 24h' lure (incident EX1550543) | 2026-11-13 | Microsoft Threat Intelligence / Guardz |
| mfs-0957 | Microsoft 365 | Intermediate redirect host in the M365-outage credential phishing chain (Cloudflare-fronted 104.21.61.38 / 172.67.205.201) | 2026-11-13 | Guardz |
| mfs-0958 | Microsoft 365 / Exchange Online | Branded SendGrid click-tracking open-redirect fronting the outage-themed M365 phishing landing page | 2026-11-13 | Mimecast |
| mfs-0959 | Microsoft 365 / Exchange Online | Default SendGrid click-tracking redirect used in the same 'Outage - <6 chars>' / 'Restore messages' campaign | 2026-11-13 | Mimecast |
| mfs-0960 | Microsoft 365 | Credential-phishing landing page behind a fake 'Microsoft 365 service health / outage restored' lure citing real incident EX1550543 | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0961 | Microsoft 365 | Sibling landing domain in the same M365-outage credential-phishing kit (themelist0.html pattern) | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0962 | Microsoft 365 | Sender/lure domain impersonating Microsoft 365 Service Health notifications | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0963 | Microsoft 365 | ESP click-tracking subdomain redirecting to the fake Microsoft sign-in page | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0964 | Microsoft 365 | Compromised/abused sender domain for the Microsoft 365 outage credential-phishing wave | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0965 | Microsoft 365 | Open-redirect / click-tracking hop in the Microsoft 365 outage phishing chain | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0966 | Microsoft 365 | Redirector hostname delivering victims to the fake Microsoft credential page | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0967 | Microsoft 365 | Abused SendGrid click-tracker fronting the Microsoft 365 outage credential-harvest page | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0968 | Microsoft 365 | Abused SendGrid click-tracker in the same Microsoft 365 service-health lure campaign | 2026-11-16 | Microsoft Threat Intelligence |
| mfs-0969 | Microsoft OneDrive / Microsoft 365 | Long keyword-stuffed lookalike domain hosting a fake OneDrive shared-file sign-in | 2026-11-17 | Phishunt |
| mfs-0970 | Microsoft 365 / Azure AD | Wildcard cPanel subdomain sprawl spoofing 'login.microsoftonline' billing-verification | 2026-11-17 | Phishunt |
| mfs-0971 | Microsoft Outlook / Office 365 | Free dynamic-DNS host serving a cloned Outlook 365 sign-in | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0972 | Microsoft 365 | Typosquat domain posing as Microsoft security notification portal | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0973 | Microsoft Word / Office | Blogspot-hosted fake Word document gateway leading to credential prompt | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0974 | Microsoft Outlook | Lookalike 'Outlook plugin' domain harvesting mailbox credentials | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0975 | Microsoft 365 | Brand-impersonating 'update required' domain with fake M365 sign-in | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0976 | Microsoft Outlook | Typosquat on a cheap TLD hosting an Outlook webmail credential form | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0977 | Office 365 | Fake 'licensing support' portal collecting Office 365 credentials | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0978 | Microsoft 365 | SKU-named lookalike domain presenting a Microsoft 365 sign-in | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0979 | Microsoft | Subdomain abuse placing 'microsoft' as the left-most label on an unrelated CN domain | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0980 | Microsoft OneDrive | Victim-specific tokenized OneDrive share lure on a SPA phishing kit (hash-routed /matpwp#/main) | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0981 | Microsoft Outlook | Per-recipient Outlook 'verify your token' credential page on shared kit infrastructure | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0982 | Microsoft Outlook | Second host reusing the identical kit path — 'outlook.' subdomain on an alert-themed lookalike | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0983 | Microsoft | Free eu.org delegation hosting a Microsoft account sign-in clone | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0984 | Office 365 | Homoglyph typosquat ('rri' for 'm') with /i/<32-hex> victim-ID credential page | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0985 | Microsoft | Fake Microsoft security-alert portal on an 'email-microsoft' lookalike domain | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0986 | Office 365 | Same /i/<hex> kit as rricrosoft-offices.org — 'office365.' subdomain on alert-themed domain | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0987 | Microsoft Live / Outlook | Spanish-language 'reactivate your account' lure on free iceiy.com hosting | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0988 | Microsoft 365 | 'microsoft' subdomain on a Citrix-themed file-share lookalike leading to an M365 credential prompt | 2026-11-17 | Phishunt / OpenPhish |
| mfs-0989 | Microsoft 365 | Vercel-hosted static clone of the Microsoft sign-in page | 2026-11-17 | OpenPhish |
| mfs-0990 | Microsoft 365 | Deceptive-subdomain typosquat on abused cPanel shared hosting (IP-named parent domain) serving a cloned Entra ID sign-in page | 2026-11-17 | phishunt.io |
| mfs-0991 | Microsoft 365 | Wildcard-subdomain typosquat variant of the same cPanel kit (repeated www./m. labels to pad the hostname) | 2026-11-17 | phishunt.io |
| mfs-0992 | Microsoft 365 / Outlook Web Access | Billing-update lure typosquat on cPanel shared hosting, 'webmail.' label to look like OWA | 2026-11-17 | phishunt.io |
| mfs-0993 | Microsoft 365 | Same billing-update cPanel kit, 'cpanel.' subdomain variant | 2026-11-17 | phishunt.io |
| mfs-0994 | Microsoft 365 | Typosquat credential harvester; triple 'www.' padding pushes the real registrable domain off-screen on mobile | 2026-11-17 | phishunt.io |
| mfs-0995 | Microsoft 365 | Random 8-char DGA-style subdomain per victim on the cPanel billing-verification kit | 2026-11-17 | phishunt.io |
| mfs-0996 | Microsoft 365 | Bare apex of the billing-verification cPanel phishing cluster (new 52-234-33-034 node) | 2026-11-17 | phishunt.io |
| mfs-0997 | Microsoft 365 | Multi-level random-label typosquat on the DigitalOcean-hosted (161.35.102.243) cPanel kit node | 2026-11-17 | phishunt.io |
| mfs-0998 | Microsoft 365 | Typosquat on new cPanel node using zero-padded octets (03-129-34-049) to evade IP-pattern IOC matching | 2026-11-17 | phishunt.io |
| mfs-0999 | Microsoft 365 | Random-subdomain variant on the zero-padded 03-129-34-049 cPanel node | 2026-11-17 | phishunt.io |
| mfs-1000 | Microsoft 365 | Typosquat credential harvester on AWS-hosted (54.37.73.97) cPanel node, zero-padded octets | 2026-11-17 | phishunt.io |
| mfs-1001 | Microsoft 365 | Sibling random-subdomain variant on the same 54-037-73-097 cPanel node | 2026-11-17 | phishunt.io |
| mfs-1002 | Microsoft 365 | Typosquat harvester on DigitalOcean node 134.209.251.140, no 'login.' label (shorter variant) | 2026-11-17 | phishunt.io |
| mfs-1003 | Microsoft 365 | Typosquat harvester on new DigitalOcean node 167.71.169.104 | 2026-11-17 | phishunt.io |
| mfs-1004 | Microsoft account (Live / MSA) | Subdomain-path spoofing on a compromised legitimate .ie domain — brand words placed entirely in DNS labels | 2026-11-17 | phishunt.io |
| mfs-1005 | Microsoft 365 (passwordless / Entra ID) | Static HTML credential-harvest page on a compromised host, RFP/proposal-sharing lure, epoch-ms filename | 2026-11-17 | phishunt.io |
| mfs-1006 | Microsoft 365 | Microsoft 365 outage (incident EX1550543) lure — credential page hosted in an attacker-controlled Oracle Cloud object-storage bucket, reached via SendGrid click-tracking redirect | 2026-11-16 | Cofense Intelligence (Flash Alert ATR 426633) |
| mfs-1007 | Microsoft 365 / Entra ID | Sneaky2FA AiTM reverse-proxy sign-in page hosted on Azure Front Door, reached via abused ActiveCampaign tracking links; steals post-MFA session cookies | 2026-11-17 | KnowBe4 ThreatLabs |
| mfs-1008 | Microsoft 365 / Entra ID | IDN/punycode homoglyph domain hosting a Sneaky2FA AiTM fake Microsoft login at /connect/ | 2026-11-17 | KnowBe4 ThreatLabs |
| mfs-1009 | Microsoft 365 / Entra ID | Abused ActiveCampaign email-marketing click-tracker used as the first hop redirecting to the Sneaky2FA fake Microsoft sign-in page | 2026-11-17 | KnowBe4 ThreatLabs |
| mfs-1010 | Microsoft 365 / Entra ID | Second abused ActiveCampaign tracking hostname for the same Sneaky2FA AiTM chain | 2026-11-17 | KnowBe4 ThreatLabs |
| mfs-1011 | Microsoft 365 / Entra ID | First-hop attacker redirector in the 'Hidden Relay' OAuth device-code phishing chain that never displays the device code to the victim | 2026-11-12 | KnowBe4 ThreatLabs |
| mfs-1012 | Microsoft 365 / Entra ID | Cloudflare Worker campaign router in the Hidden Relay device-code kit; carries the campaign token in ?_k= and mints the victim transfer token | 2026-11-12 | KnowBe4 ThreatLabs |
| mfs-1013 | Microsoft 365 / Entra ID | Cloudflare Worker hosting the Turnstile anti-bot gate and the fake Microsoft sign-in kit page for the Hidden Relay device-code campaign | 2026-11-12 | KnowBe4 ThreatLabs |
| mfs-1014 | Microsoft 365 / Entra ID | Backend Worker serving the device-authorization endpoints (POST /api/device/start with X-Worker-Token header) that silently requests the code from Microsoft on the victim's behalf | 2026-11-12 | KnowBe4 ThreatLabs |
| mfs-1015 | Microsoft 365 / Entra ID | Per-victim relay page URL in the Hidden Relay device-code kit (/link/ + 32 hex chars), auto-approving the device grant without showing the code | 2026-11-12 | KnowBe4 ThreatLabs |
| mfs-1016 | Microsoft 365 | Multi-hop redirector in Microsoft 365 outage (EX1550543) lure chain leading to cloned Entra ID sign-in page | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1017 | Microsoft 365 | Redirect/phishing parent domain used in Exchange Online outage credential-harvest campaign | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1018 | Microsoft 365 | Random-subdomain redirector hop between SendGrid click-tracking link and fake Microsoft sign-in page | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1019 | Microsoft 365 | Tokenized per-recipient redirect (/r/cloupriv/?token=) fronting the Microsoft credential-harvest page | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1020 | Microsoft 365 | Phishing apex domain (nonsense-word DGA-style label on cheap .cyou TLD) in outage-lure chain | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1021 | Microsoft 365 | Fake Microsoft /common sign-in endpoint with per-victim ?key= parameter (mimics Entra ID common tenant path) | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1022 | Microsoft 365 | Attacker-controlled click-tracking redirector on a campaign sender domain (outage-restore lure) | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1023 | Microsoft 365 | Mail/link subdomain on attacker sender domain used to relay victims to the spoofed Microsoft 365 login | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1024 | Microsoft 365 | Numbered SendGrid-style click-tracking host redirecting to the Microsoft credential-harvest page | 2026-11-18 | Cyber Security News (Microsoft Threat Intelligence campaign reporting) |
| mfs-1025 | Microsoft 365 / Entra ID | Subdomain-prefix typosquat — 'login.microsoftonline' placed as a subdomain label on an attacker-owned .at domain to fake the real sign-in host | 2026-11-20 | Phishunt (Microsoft tracker) |
| mfs-1026 | Microsoft 365 / Entra ID | Subdomain-prefix typosquat abusing a lookalike HR-SaaS domain (bamboohr.app) to host a fake Entra sign-in page | 2026-11-19 | OpenPhish (via Phishunt) |
| mfs-1027 | Microsoft 365 | Typosquat / hyphen-insertion lookalike domain hosting a cloned Microsoft credential-harvesting login form | 2026-11-20 | Phishunt (Microsoft tracker) |
| mfs-1028 | Microsoft 365 / Copilot | Copilot-themed lure on a 'm365cloud-microsoft' combosquat domain leading to a fake Microsoft sign-in page | 2026-11-20 | Phishunt (Microsoft tracker) |
| mfs-1029 | Microsoft Outlook / Exchange Online | Fake Exchange Online quarantine-digest notification driving victims to an Outlook credential-capture page | 2026-11-20 | Phishunt (Microsoft tracker) |
| mfs-1030 | Microsoft Hotmail / Live | Brandjacked Hotmail apex domain fronting credential-harvesting subdomains (api./usdt.) | 2026-11-20 | Phishunt (Microsoft tracker) |
| mfs-1031 | Microsoft 365 / SharePoint | Device-code OAuth phishing — HTML/SVG attachment redirector to a verification gate and counterfeit SharePoint workspace that feeds the real login.microsoftonline.com/common/oauth2/deviceauth flow | 2026-11-19 | Hornetsecurity Threat Intelligence Lab |
| mfs-1032 | Microsoft 365 / SharePoint | Device-code OAuth phishing infrastructure (second host on the same .cfd lure domain) | 2026-11-19 | Hornetsecurity Threat Intelligence Lab |
| mfs-1033 | Microsoft 365 / SharePoint | Payment-themed document lure host in the device-code OAuth phishing chain to Microsoft sign-in | 2026-11-19 | Hornetsecurity Threat Intelligence Lab |
| mfs-1034 | Microsoft 365 | Billing/invoice-themed lure host in the same device-code phishing cluster targeting M365 token issuance | 2026-11-19 | Hornetsecurity Threat Intelligence Lab |
| mfs-1035 | Microsoft 365 / SharePoint | Cloudflare Workers-hosted redirector (payment-advice variant) into the Microsoft device-code consent flow | 2026-11-19 | Hornetsecurity Threat Intelligence Lab |
| mfs-1036 | Microsoft 365 | Brand-suffix lookalike domain on .studio TLD posing as a Microsoft 365 security-awareness portal to harvest credentials | 2026-11-23 | Phishunt |
| mfs-1037 | Microsoft Outlook | Typosquat/brand-impersonation domain mimicking Outlook mailbox notification alerts (quarantine/held-mail lure) | 2026-11-22 | Phishunt |
| mfs-1038 | Microsoft | Typosquat apex domain (extra 'h' after microsoft) fronting a wildcard-subdomain Microsoft credential-phishing cluster | 2026-11-22 | Phishunt |
| mfs-1039 | Microsoft Defender SmartScreen | Typosquat subdomain abusing a Microsoft security-product name to make the phishing lure look like a safety warning | 2026-11-22 | Phishunt |
| mfs-1040 | Microsoft Rewards | Typosquat subdomain using a Microsoft Rewards incentive lure to funnel victims to a Microsoft account sign-in | 2026-11-22 | Phishunt |
| mfs-1041 | Microsoft | Wildcard/catch-all subdomain on the microsofth.com typosquat cluster, indicating per-victim hostname generation | 2026-11-22 | Phishunt |
| mfs-1042 | Microsoft | Short-label subdomain on the microsofth.com typosquat cluster hosting Microsoft sign-in content | 2026-11-22 | Phishunt |
| mfs-1043 | Microsoft Learn | Typosquat subdomain cloning the Microsoft Learn hostname pattern to lend legitimacy before a credential prompt | 2026-11-22 | Phishunt |
| mfs-1044 | Microsoft | Infrastructure-style subdomain on the microsofth.com typosquat cluster | 2026-11-22 | Phishunt |
| mfs-1045 | Microsoft Outlook | Typosquat subdomain presenting a webmail/Outlook sign-in to harvest Microsoft 365 credentials | 2026-11-22 | Phishunt |
| mfs-1046 | Microsoft OneDrive | Brand-as-domain abuse — 'onedrive' registered as the second-level label under .business to fake a OneDrive for Business file-share sign-in | 2026-11-21 | Phishunt |
| mfs-1047 | Microsoft Entra ID | Subdomain-prefix spoof placing 'login.microsoftonline' in front of a compromised/abused mybluehost.me shared-hosting domain | 2026-11-20 | Phishunt |
| mfs-1048 | Microsoft Entra ID | Deep-nested subdomain spoof ('mail.login.microsoftonline.*') on abused mybluehost.me hosting, targeting Outlook/Exchange sign-in | 2026-11-20 | Phishunt |
| mfs-1049 | Microsoft 365 | Credential-harvest sign-in clone hosted on abused Azure App Service (*.azurewebsites.net) so the page inherits a Microsoft-owned TLS cert and domain | 2026-11-23 | OpenPhish (public feed) |
| mfs-1050 | Microsoft Outlook | Typosquat/lookalike domain serving a fake Outlook webmail UI (urlscan title "mail.outlookmails.de - mail UI") for credential capture | 2026-11-23 | Phishunt |
| mfs-1051 | Microsoft Outlook | Fake Outlook webmail login host on the outlookmails.de lookalike apex | 2026-11-23 | Phishunt |
| mfs-1052 | Microsoft Outlook | Free-PaaS-hosted Outlook sign-in clone on Vercel (disposable *.vercel.app subdomain, instant HTTPS) | 2026-11-23 | Phishunt |
| mfs-1053 | Microsoft 365 (billing/licensing lure) | Deceptive-subdomain chain on a cPanel default hostname — random 8-char label + 'login.microsoftonline-billing-verification-secured-help' prefixed onto *.cpanel.site so the visible left-hand side reads as Microsoft | 2026-11-23 | Phishunt |
| mfs-1054 | Microsoft 365 (billing/licensing lure) | Staging/'test' sibling of the same cPanel deceptive-subdomain kit — same IP-named cpanel.site host, indicating an active kit under development | 2026-11-23 | Phishunt |
| mfs-1055 | Microsoft Teams | Teams meeting-invite typosquat used as a credential/consent lure landing page (bulk-registered .online cluster) | 2026-11-19 | TweetFeed (@patialavii on X) |
| mfs-1056 | Microsoft Teams | Plural variant in the same bulk-registered Teams-invite typosquat cluster | 2026-11-19 | TweetFeed (@patialavii on X) |
| mfs-1057 | Microsoft Teams | Teams-meeting typosquat in the same cluster; urlscan shows it currently serving a registrar default page, i.e. staged infrastructure not yet weaponised | 2026-11-19 | TweetFeed (@patialavii on X) |
| mfs-1058 | Microsoft Teams / Copilot | AI-themed Teams lookalike domain (Teams+Copilot branding) used for credential phishing lures | 2026-11-08 | TweetFeed (@Malwarehunterr on X) |
| mfs-1059 | Microsoft 365 | Homoglyph/letter-insertion typosquat ('micros-l-oft') on an 'accounts.' subdomain with a billing/subscription-renewal lure | 2026-11-07 | TweetFeed (@masaomi346 on X) |
| mfs-1060 | Microsoft 365 / Entra ID | CAPTCHA-gated AiTM: a bot-check interstitial (captcha.html) filters sandboxes before relaying the victim to a live Entra ID sign-in, with the target address pre-filled via the ?email= parameter | 2026-11-07 | TweetFeed (@crimeonprem on X) |
| mfs-1061 | Microsoft Outlook | Newly registered combosquat domain hosting fake Outlook sign-in / client download lure | 2026-11-23 | phishunt.io |
| mfs-1062 | Microsoft 365 | Typosquat of login.microsoftonline.com used as credential-harvesting portal | 2026-11-23 | phishunt.io |
| mfs-1063 | OneDrive / SharePoint | Long-string keyword-stuffed lure domain on cheap .autos TLD impersonating a shared document | 2026-11-23 | phishunt.io |
| mfs-1064 | Microsoft OneDrive | Combosquat domain serving fake 'shared document' OneDrive sign-in page | 2026-11-23 | phishunt.io |
| mfs-1065 | Microsoft Teams | Typosquat (microsoft+teams/team-setup) on .top TLD for Teams meeting-join credential lure | 2026-11-23 | phishunt.io |
| mfs-1066 | Microsoft 365 | Brand-impersonation domain posing as an official Microsoft 365 app portal | 2026-11-23 | phishunt.io |
| mfs-1067 | Microsoft 365 | Keyword-stuffed auth-themed lure domain on .live TLD prompting M365 sign-in for 'private files' | 2026-11-23 | phishunt.io |
| mfs-1068 | Microsoft Outlook | Pluralized typosquat of Outlook on novelty .life TLD | 2026-11-22 | phishunt.io |
| mfs-1069 | Microsoft Outlook | Short-suffix typosquat domain used for Outlook webmail credential capture | 2026-11-22 | phishunt.io |
| mfs-1070 | Microsoft Outlook | Doubled-letter typosquat ('maill') for Outlook mail sign-in page | 2026-11-22 | phishunt.io |
| mfs-1071 | Microsoft Outlook | Homoglyph typosquat substituting digit 1 for letter l in 'outlook' | 2026-11-22 | phishunt.io |
| mfs-1072 | Microsoft OneDrive | Combosquat domain hosting fake OneDrive document-preview credential page | 2026-11-22 | phishunt.io |
| mfs-1073 | Microsoft Office 365 | Victim-specific combosquat embedding a target law firm's name with Office 365 branding | 2026-11-22 | phishunt.io |
| mfs-1074 | Microsoft | Homoglyph typosquat using 'rn' to mimic 'm' in microsoftmail | 2026-11-22 | phishunt.io |
| mfs-1075 | Microsoft 365 | Brand combosquat used for fake PDF/document-viewer sign-in prompts | 2026-11-22 | phishunt.io |
| mfs-1076 | Microsoft 365 | Exact brand string 'microsoftonline' on an unrelated novelty TLD | 2026-11-22 | phishunt.io |
| mfs-1077 | Microsoft | Numeric-suffix brand impersonation domain (randomized registration pattern) | 2026-11-22 | phishunt.io |
| mfs-1078 | Microsoft Outlook | Prefix-hyphen typosquat posing as mobile Outlook sign-in | 2026-11-22 | phishunt.io |
| mfs-1079 | Microsoft Hotmail / Live | Typosquat domain targeting legacy Hotmail/Live account holders | 2026-11-22 | phishunt.io |
| mfs-1080 | Microsoft Outlook | Sibling TLD registration of the outlookmc typosquat cluster | 2026-11-21 | phishunt.io |
| mfs-1081 | Microsoft Outlook | Character-swap typosquat ('mall' for 'mail') hosting Outlook sign-in clone | 2026-11-21 | phishunt.io |
| mfs-1082 | Microsoft Outlook | Generic combosquat domain used as Outlook webmail credential portal | 2026-11-21 | phishunt.io |
| mfs-1083 | Microsoft Outlook | Account-verification themed combosquat for credential harvesting | 2026-11-21 | phishunt.io |
| mfs-1084 | Microsoft OneDrive | Shared-document lure domain impersonating OneDrive file access | 2026-11-21 | phishunt.io |
| mfs-1085 | Microsoft 365 | Fake 'Microsoft Connect' corporate portal collecting Entra ID credentials | 2026-11-21 | phishunt.io |
| mfs-1086 | Microsoft | Locale-suffix brand impersonation domain on .live TLD | 2026-11-21 | phishunt.io |
| mfs-1087 | Microsoft | French-language security-alert combosquat for credential phishing | 2026-11-20 | phishunt.io |
| mfs-1088 | Microsoft Outlook | Brand combosquat on commerce TLD hosting Outlook sign-in clone | 2026-11-20 | phishunt.io |
| mfs-1089 | Microsoft Outlook | Organization-targeted combosquat pairing Outlook with a victim-brand token | 2026-11-20 | phishunt.io |
| mfs-1090 | Microsoft | Pluralized brand typosquat on .pro TLD | 2026-11-20 | phishunt.io |
| mfs-1091 | Microsoft 365 | Suffix-appended typosquat of microsoftonline.com for M365 sign-in capture | 2026-11-20 | phishunt.io |
| mfs-1092 | Microsoft / Copilot | AI/Copilot-themed brand impersonation domain luring developer sign-ins | 2026-11-20 | phishunt.io |
| mfs-1093 | Microsoft 365 | Digit-shift typosquat of 'microsoft365' (364 for 365) | 2026-11-20 | phishunt.io |
| mfs-1094 | Microsoft 365 | Mailbox 'sync required' themed combosquat on .online TLD | 2026-11-19 | phishunt.io |
| mfs-1095 | Microsoft Hotmail / Live | Victim-organization combosquat appending '-hotmail' to a target name | 2026-11-19 | phishunt.io |
| mfs-1096 | Microsoft Outlook | Finance-themed Outlook combosquat used for invoice/payment credential lures | 2026-11-19 | phishunt.io |
| mfs-1097 | Microsoft Outlook | Innocuous-looking Outlook combosquat on .info TLD used as sign-in host | 2026-11-19 | phishunt.io |
| mfs-1098 | Microsoft Outlook | 'Demo'-labelled staging domain for an Outlook credential-harvesting kit | 2026-11-19 | phishunt.io |
| mfs-1099 | Microsoft OneDrive | Random-suffix OneDrive combosquat on .click TLD | 2026-11-19 | phishunt.io |
| mfs-1100 | Microsoft OneDrive | Shared-document lure combosquat for OneDrive sign-in capture | 2026-11-19 | phishunt.io |
| mfs-1101 | Microsoft | Random-token brand impersonation domain from a bulk-registration cluster | 2026-11-19 | phishunt.io |
| mfs-1102 | Microsoft | Account-recovery themed combosquat harvesting credentials and MFA codes | 2026-11-19 | phishunt.io |
| mfs-1103 | Microsoft | Fake Microsoft programme/partner site fronting an M365 sign-in page | 2026-11-19 | phishunt.io |
| mfs-1104 | Microsoft 365 / Entra ID | Explicit auth-themed combosquat impersonating Entra ID sign-in | 2026-11-19 | phishunt.io |
| mfs-1105 | Microsoft | Target-name-prefixed combosquat impersonating a tenant-specific Microsoft portal | 2026-11-19 | phishunt.io |
| mfs-1106 | Microsoft 365 | Healthcare-organization combosquat posing as that tenant's Microsoft login | 2026-11-19 | phishunt.io |
| mfs-1107 | Microsoft OneDrive | Media-company combosquat impersonating a branded OneDrive share portal | 2026-11-18 | phishunt.io |
| mfs-1108 | Microsoft Outlook | Mailbox-sync lure combosquat on .cfd TLD | 2026-11-18 | phishunt.io |
| mfs-1109 | Microsoft Outlook | Finance-lure combosquat on .sbs TLD mixing a fake exchange name with Outlook | 2026-11-18 | phishunt.io |
| mfs-1110 | Microsoft OneDrive | Fake 'OneDrive Personal Vault' sign-in combosquat | 2026-11-18 | phishunt.io |
| mfs-1111 | Microsoft | Gaming-themed brand impersonation domain fronting a Microsoft account sign-in | 2026-11-18 | phishunt.io |
| mfs-1112 | Microsoft Azure / Entra ID | Enterprise 'Sovereign Cloud' themed impersonation domain targeting admin credentials | 2026-11-18 | phishunt.io |
| mfs-1113 | Microsoft | Generic brand-impersonation domain from a bulk 'microsoft<word>' registration batch | 2026-11-18 | phishunt.io |
| mfs-1114 | Microsoft 365 | Compound typosquat merging microsoftonline and live brand strings | 2026-11-18 | phishunt.io |
| mfs-1115 | Microsoft 365 | Dropped-character typosquat of microsoftonline ('nline') for sign-in capture | 2026-11-18 | phishunt.io |
| mfs-1116 | Microsoft Bookings | Microsoft Bookings themed combosquat (z-suffix) on .top TLD | 2026-11-18 | phishunt.io |
| mfs-1117 | Microsoft Bookings | Sibling .com registration of the microsoftbookingz lure cluster | 2026-11-18 | phishunt.io |
| mfs-1118 | Microsoft 365 | Exact 'microsoft365' brand string on .studio TLD, apex of a known phishing host tree | 2026-11-18 | phishunt.io |
| mfs-1119 | Microsoft | Fake Microsoft support portal on .help TLD (tech-support + credential phishing) | 2026-11-18 | phishunt.io |
| mfs-1120 | Microsoft OneDrive | Security-themed OneDrive combosquat implying a scan/quarantine of shared files | 2026-11-18 | phishunt.io |
| mfs-1121 | Microsoft Outlook | Generic Outlook combosquat hosting a cloned sign-in page | 2026-11-17 | phishunt.io |
| mfs-1122 | Microsoft Outlook | Automation/bot-themed Outlook combosquat for mailbox credential capture | 2026-11-17 | phishunt.io |
| mfs-1123 | Microsoft Outlook | Reporting-themed Outlook combosquat used as credential landing page | 2026-11-17 | phishunt.io |
| mfs-1124 | Microsoft Office 365 | Account-abbreviation combosquat ('accs') impersonating Office 365 login | 2026-11-17 | phishunt.io |
| mfs-1125 | Microsoft 365 | Security-alert combosquat merging microsoftonline + security on .shop TLD | 2026-11-17 | phishunt.io |
| mfs-1126 | Microsoft 365 | Digit-shift typosquat of microsoft365 on .net TLD | 2026-11-17 | phishunt.io |
| mfs-1127 | Microsoft Teams | Dropped-character typosquat of Microsoft Teams used for meeting-join sign-in lures | 2026-11-17 | phishunt.io |
| mfs-1128 | Microsoft 365 | Dual-brand combosquat (Microsoft + SAP) targeting enterprise SSO credentials | 2026-11-17 | phishunt.io |
| mfs-1129 | Microsoft 365 | Phishing kit on a hijacked/throwaway domain; fake M365 login with offer_ref pointing at the real login.microsoftonline.com to look legitimate | 2026-11-24 | OpenPhish |
| mfs-1130 | Microsoft Outlook | Credential-harvesting Outlook sign-in clone hosted on free Render.com PaaS subdomain | 2026-11-25 | OpenPhish (via phishunt.io) |
| mfs-1131 | Microsoft Outlook / Office 365 | Deep-subdomain brand stuffing — 'outlook.accountonline-officeportal' prefixed onto an unrelated attacker apex to fake an Outlook account portal | 2026-11-24 | phishunt.io Microsoft brand feed |
| mfs-1132 | Microsoft 365 (Entra ID device code) | OAuth device-code phishing — fake Microsoft 'identity verification' page tells victim to generate a code and paste it into the real Microsoft sign-in, granting attacker tokens; reached via Constant Contact → S3 → Cloudflare Workers redirect chain | 2026-11-23 | ThreadLinqs Intelligence (TL-2026-6716) |
| mfs-1133 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS post-takedown host — fake shared-document lure driving OAuth device-code flow against Microsoft 365 | 2026-11-10 | VMRay Labs |
| mfs-1134 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host — 'shared docx / online auth' lure fronting Microsoft device-code account takeover | 2026-11-05 | VMRay Labs |
| mfs-1135 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host — organization-branded 'portail' lure leading to Microsoft device-code token theft | 2026-11-04 | VMRay Labs |
| mfs-1136 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host — victim-org-branded portal page fronting Microsoft OAuth device-code flow | 2026-10-31 | VMRay Labs |
| mfs-1137 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host — 'view secure document' lure driving Microsoft device-code consent | 2026-11-02 | VMRay Labs |
| mfs-1138 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host on Vercel — WeTransfer file-access lure that pivots to Microsoft device-code authentication | 2026-11-03 | VMRay Labs |
| mfs-1139 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host on attacker-registered apex — 'tokenaccess' subdomain serving the device-code lure | 2026-11-05 | VMRay Labs |
| mfs-1140 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host — e-signature themed lure fronting Microsoft device-code account takeover | 2026-11-05 | VMRay Labs |
| mfs-1141 | Microsoft 365 (Entra ID device code) | EvilTokens PhaaS host — document-management lure leading to Microsoft OAuth device-code token theft | 2026-11-05 | VMRay Labs |
| mfs-1142 | Microsoft 365 | AI-generated fake Microsoft sign-in page built with Hugging Face DeepSite and hosted free on Hugging Face Spaces; exfiltrates credentials to a Telegram bot then redirects to real Outlook | 2026-11-24 | Aikido Security |
| mfs-1143 | Microsoft 365 | DeepSite-built Microsoft credential page on Hugging Face Spaces, branded as a target university's 'security portal' | 2026-11-24 | Aikido Security |
| mfs-1144 | Microsoft 365 | DeepSite-built Microsoft sign-in clone on Hugging Face Spaces using a randomized owner handle and benign-looking Space name | 2026-11-24 | Aikido Security |
| mfs-1145 | Microsoft 365 | Multi-hop redirect chain into reverse-proxy (AiTM) fake Microsoft sign-in; recipient address carried in URL fragment | 2026-11-27 | ThreadLinqs Intel (TL-2026-6951) |
| mfs-1146 | Microsoft 365 | Intermediate hop in 'Verify Access' AiTM chain; random subdomain + hex path per recipient | 2026-11-27 | ThreadLinqs Intel (TL-2026-6951) |
| mfs-1147 | Microsoft 365 | Fake verification screen hop preceding Microsoft credential-harvest page | 2026-11-27 | ThreadLinqs Intel (TL-2026-6951) |
| mfs-1148 | Microsoft 365 | Compromised legitimate site used as redirector to Microsoft AiTM phishing page | 2026-11-27 | ThreadLinqs Intel (TL-2026-6951) |
| mfs-1149 | Microsoft 365 / Entra ID | NakedPages phishing framework backend reached via abuse of the real login.microsoftonline.com OAuth authorize endpoint (prompt=none redirect_uri abuse) | 2026-11-20 | Eye Security Labs |
| mfs-1150 | Microsoft 365 / Entra ID | NakedPages credential-harvest page delivered via login.microsoftonline.com open-redirect-style OAuth redirect_uri abuse | 2026-11-20 | Eye Security Labs |
| mfs-1151 | Microsoft 365 / Entra ID | NakedPages variant; Cloudflare Worker CAPTCHA gate fronting the fake Microsoft sign-in | 2026-11-20 | Eye Security Labs |
| mfs-1152 | Microsoft Account / Azure | Typosquat subdomain ('securitusa') on a shared hosting provider serving a fake Microsoft account security page | 2026-11-26 | PhishPin |
| mfs-1153 | Microsoft Account | Free dev-platform hosting (Replit) serving a 'account verification' credential-harvest clone | 2026-11-26 | PhishPin |
| mfs-1154 | Outlook / Microsoft Account | S3 static-website bucket abuse; brand keywords stuffed into the bucket name to spoof an auth redirect | 2026-11-26 | PhishPin |
| mfs-1155 | Microsoft 365 | EvilTokens OAuth device-code phishing; document-review lure page issues a real Microsoft device code to steal access/refresh tokens | 2026-10-30 | Cybersecurity News / GBHackers (EvilTokens post-takedown tracking) |
| mfs-1157 | Microsoft 365 / Exchange Online | EvilTokens device-code phishing using a voicemail-notification lure | 2026-10-30 | Cybersecurity News (EvilTokens) |
| mfs-1161 | Microsoft 365 | EvilTokens device-code phishing with procurement 'bid invitation' portal lure | 2026-11-10 | Cybersecurity News (EvilTokens) |
| mfs-1170 | Microsoft 365 / Entra ID | Fake corporate 'SSO work portal' lure in the AI-event invitation campaign; 'Continue with Microsoft' leads to Kali365 device-code or VoidProxy AiTM capture | 2026-11-21 | ThreatDefence |
| mfs-1171 | Microsoft 365 / Entra ID | Event-registration SSO lure funnelling victims to Microsoft sign-in proxies (VoidProxy AiTM) | 2026-11-21 | ThreatDefence |
| mfs-1172 | Microsoft 365 / Entra ID | Fake meeting-SSO portal in the same event-invite cluster; harvests Microsoft work-account sessions | 2026-11-21 | ThreatDefence |
| mfs-1173 | Microsoft 365 (Anthropic/Claude-themed lure) | Typosquat AI-webinar invite ('webinnar') offering free AI access; 'Sign in with Microsoft' routes to a Microsoft sign-in proxy | 2026-11-21 | ThreatDefence |
| mfs-1174 | Microsoft 365 / Google Workspace | Event-registration lure domain in the AI-events cluster presenting both Microsoft and Google sign-in options | 2026-11-21 | ThreatDefence |
| mfs-1175 | Microsoft 365 / Entra ID | Help-desk impersonation (voice/SMS/Teams) driving victims to a fake Microsoft passkey/MFA enrollment page; AiTM session-token theft | 2026-11-24 | CyberPress |
| mfs-1176 | Microsoft 365 / Entra ID | Fake Microsoft passkey-setup portal used for AiTM credential and session capture, then Graph API abuse | 2026-11-24 | CyberPress |
| mfs-1177 | Microsoft 365 / Entra ID | Wildcard-subdomain phishing (e.g. contoso.add-passkey.com) embedding the victim's company name to spoof a Microsoft passkey enrollment flow | 2026-11-24 | CyberPress |

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

### mfs-0889 — Microsoft Teams

```text
https://brimembal.com/schedule-microsoft-teams.meeting
```

- **Domain:** `brimembal.com`
- **Technique:** Compromised legitimate site hosting a Teams "scheduled meeting" lure path that chains to an M365 credential form
- **Detection:** Alert on inbound URLs where the path contains 'microsoft-teams' or 'teams.meeting' but the registrable domain is not microsoft.com/teams.microsoft.com
- **Source:** TweetFeed (via phishunt.io) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0890 — Office 365

```text
https://viewpdfdocument2.weebly.com/
```

- **Domain:** `viewpdfdocument2.weebly.com`
- **Technique:** Free-hosting (Weebly) fake document gate — "Sign in With Your Office 365 Email To Review PDF Document"
- **Detection:** Hunt proxy logs for *.weebly.com page titles/forms containing 'Office 365' plus a password field; Weebly is never an M365 auth origin
- **Source:** PhishDestroy — https://phishdestroy.io/domain/viewpdfdocument2.weebly.com/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0891 — Microsoft Excel / Microsoft 365

```text
https://viewcompleteddocument.weebly.com/
```

- **Domain:** `viewcompleteddocument.weebly.com`
- **Technique:** Weebly-hosted Excel-branded "Sign in to view the document" credential form
- **Detection:** Flag POSTs from *.weebly.com containing email+password params; correlate with Excel/Office logo image hashes
- **Source:** PhishDestroy — https://phishdestroy.io/domain/viewcompleteddocument.weebly.com/
- **Status:** active
- **First seen:** 2026-11-09

### mfs-0892 — Microsoft 365

```text
https://dmpmnnu-smoky-96.vercel.app
```

- **Domain:** `dmpmnnu-smoky-96.vercel.app`
- **Technique:** Vercel-hosted clone of the ConvergedSignIn page ("Email, phone, or Skype" field, Next button)
- **Detection:** Block/alert on *.vercel.app responses whose DOM contains 'Email, phone, or Skype' or msauth CSS references; 17/92 VT detections
- **Source:** PhishDestroy — https://phishdestroy.io/domain/dmpmnnu-smoky-96.vercel.app/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0893 — Microsoft 365

```text
https://ucsg365.vercel.app
```

- **Domain:** `ucsg365.vercel.app`
- **Technique:** Spanish-language ("Iniciar sesión") Microsoft sign-in clone on Vercel with custom background art
- **Detection:** Hunt randomized *.vercel.app hostnames serving localized Microsoft sign-in cards; GSB flags as social engineering
- **Source:** PhishDestroy — https://phishdestroy.io/domain/ucsg365.vercel.app/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0894 — Microsoft 365

```text
https://www.ucsg365.vercel.app
```

- **Domain:** `www.ucsg365.vercel.app`
- **Technique:** www redirector feeding the ucsg365.vercel.app Microsoft sign-in clone
- **Detection:** Resolve and block both apex and www forms of flagged *.vercel.app phishing hosts — redirectors often outlive takedowns
- **Source:** PhishDestroy — https://phishdestroy.io/domain/ucsg365.vercel.app/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0895 — Microsoft SharePoint

```text
https://newlogss.github.io/
```

- **Domain:** `newlogss.github.io`
- **Technique:** GitHub Pages SharePoint-branded loader page pulling real aadcdn.msauth.net / logincdn.msauth.net assets to look authentic
- **Detection:** Alert when a non-Microsoft origin loads aadcdn.msauth.net or logincdn.msauth.net resources; 22/92 VT, urlscan 100/100 Microsoft brand
- **Source:** PhishDestroy — https://phishdestroy.io/domain/newlogss.github.io/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0896 — Outlook Web App (OWA)

```text
https://owa-mail-auth.web.app/
```

- **Domain:** `owa-mail-auth.web.app`
- **Technique:** Firebase Hosting OWA kit — HTML title 'Outlook' with cloaked/blank body served to scanners
- **Detection:** Block the web.app sibling of any flagged firebaseapp.com host; hunt 'Outlook' <title> with near-empty body on *.web.app
- **Source:** PhishDestroy — https://phishdestroy.io/domain/owa-mail-auth.web.app/
- **Status:** active
- **First seen:** 2026-11-01

### mfs-0897 — Microsoft OneDrive

```text
https://onedrive-4-nine.vercel.app
```

- **Domain:** `onedrive-4-nine.vercel.app`
- **Technique:** Credential-harvesting fake OneDrive/Microsoft sign-in page hosted on free Vercel subdomain
- **Detection:** Alert on outbound HTTPS to *.vercel.app hosts whose subdomain contains onedrive/outlook/office tokens; these are never Microsoft-owned
- **Source:** phishunt.io (Microsoft tracker, updated hourly) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0899 — Microsoft 365 / OneDrive

```text
https://site.com-microsoftonline-ondrive.ca
```

- **Domain:** `site.com-microsoftonline-ondrive.ca`
- **Technique:** Typosquat using 'com-microsoftonline-ondrive' as a registrable label to fake a Microsoft hostname chain
- **Detection:** Regex DNS/proxy logs for labels containing 'com-microsoft' or 'ondrive' — legitimate Microsoft auth is only *.microsoftonline.com
- **Source:** phishunt.io (Microsoft tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0905 — Microsoft

```text
https://index-html.info
```

- **Domain:** `index-html.info`
- **Technique:** German-language fake Microsoft 'Anmelden' sign-in card behind a 308 redirect, Hetzner-hosted (46.225.73.32)
- **Detection:** Pivot on IP 46.225.73.32 and on generic/throwaway .info domains serving Microsoft logon HTML with Let's Encrypt certs
- **Source:** PhishDestroy — https://phishdestroy.io/domain/index-html.info/
- **Status:** active
- **First seen:** 2026-11-08

### mfs-0907 — Microsoft 365 (via fake AI/aerospace event lures)

```text
https://eventrsvp.app
```

- **Domain:** `eventrsvp.app`
- **Technique:** Kali365 device-code phishing + VoidProxy AiTM apex lure domain (fake OpenAI/SpaceX event RSVP)
- **Detection:** Correlate visits to event-RSVP domains with Entra ID device-code auth events (AppId 29d9ed98-a469-4536-ade2-f981bc1d605e) within minutes
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0908 — Microsoft 365 (via fake Anthropic event lure)

```text
https://rsvpconnect-events.com
```

- **Domain:** `rsvpconnect-events.com`
- **Technique:** Apex lure domain fronting Kali365 device-code and VoidProxy reverse-proxy sign-in pages
- **Detection:** Block apex plus wildcard subdomains; operator rotates vendor-name subdomains every few weeks on a stable apex
- **Source:** Push Security — https://pushsecurity.com/blog/ai-themed-fake-event-campaign-analysis
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0910 — Microsoft

```text
https://signinwith-microsoft.sbs
```

- **Domain:** `signinwith-microsoft.sbs`
- **Technique:** Newly registered sign-in-themed lookalike domain on abused .sbs TLD
- **Detection:** Block .sbs/.cfd/.icu/.top wholesale for auth traffic; alert on NRDs containing 'signin'+'microsoft'
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0911 — Microsoft Hotmail / Outlook

```text
https://pro-hotmail.com
```

- **Domain:** `pro-hotmail.com`
- **Technique:** Newly registered Hotmail brand-lookalike domain staged for credential harvesting
- **Detection:** Alert on NRD labels containing hotmail/outlook/live outside Microsoft's registrar footprint (MarkMonitor)
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0912 — Microsoft Outlook

```text
https://outlook-mailsecure.com
```

- **Domain:** `outlook-mailsecure.com`
- **Technique:** Newly registered 'mail security' themed Outlook lookalike (classic mailbox-quota/secure-message lure pattern)
- **Detection:** Hunt NRDs matching outlook-(mail|secure|verify|shield)*; pair with first-seen-in-tenant URL click telemetry
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0913 — Microsoft Office 365

```text
https://office365web.com
```

- **Domain:** `office365web.com`
- **Technique:** Newly registered Office 365 brand-lookalike domain
- **Detection:** Treat any apex containing 'office365' as non-Microsoft; Microsoft retired that naming for sign-in hostnames
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0914 — Microsoft Office 365

```text
https://office365max.com
```

- **Domain:** `office365max.com`
- **Technique:** Newly registered Office 365 brand-lookalike domain
- **Detection:** Block office365* apexes; correlate with Defender for Office 365 URL-click events for first-contact users
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0915 — Microsoft

```text
https://microsoftreset.com
```

- **Domain:** `microsoftreset.com`
- **Technique:** Newly registered password-reset themed Microsoft lookalike
- **Detection:** High-priority block: 'reset'/'recovery' + microsoft in an apex is a near-certain credential-reset lure
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0916 — Microsoft / Outlook mail

```text
https://microsoftmails.com
```

- **Domain:** `microsoftmails.com`
- **Technique:** Newly registered Microsoft mail-themed lookalike domain
- **Detection:** Alert on microsoft(mail|mails|email)* apex registrations; also check for matching MX records used for lure delivery
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0917 — Microsoft OneDrive / SharePoint

```text
https://microsoft-oneshare.com
```

- **Domain:** `microsoft-oneshare.com`
- **Technique:** Newly registered file-share themed lookalike for shared-document sign-in lures
- **Detection:** Hunt apexes blending microsoft with share/onedrive/sharepoint tokens; these front fake 'review document' auth pages
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0918 — Microsoft

```text
https://microsoftatgtcdc.com
```

- **Domain:** `microsoftatgtcdc.com`
- **Technique:** Newly registered random-suffix Microsoft lookalike (bulk-registration pattern)
- **Detection:** Flag microsoft + 4-8 random consonant string apexes; typically registered in batches by the same registrar account
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0919 — Microsoft 365

```text
https://microsoft365.art
```

- **Domain:** `microsoft365.art`
- **Technique:** Newly registered exact brand match on a low-reputation TLD
- **Detection:** Exact brand string on a non-Microsoft TLD (.art, .homes, .sbs, .cfd) is an automatic block candidate
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0920 — Microsoft

```text
https://microsoftretailer.com
```

- **Domain:** `microsoftretailer.com`
- **Technique:** Newly registered Microsoft brand-lookalike domain (licensing/reseller lure theme)
- **Detection:** Correlate NRD with inbound mail referencing license renewal or reseller invoices
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0921 — Microsoft Outlook

```text
https://houseprice-outlook.app
```

- **Domain:** `houseprice-outlook.app`
- **Technique:** Newly registered compound-word Outlook lookalike on .app TLD
- **Detection:** Hunt *-outlook.app / outlook-*.app NRDs; .app forces HTTPS so TLS-cert transparency logs catch these early
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0922 — Microsoft

```text
https://s3-microsoft.com
```

- **Domain:** `s3-microsoft.com`
- **Technique:** Newly registered infrastructure-themed Microsoft lookalike (fake CDN/storage host for phish assets)
- **Detection:** Block cdn-/s3-/storage- prefixed microsoft lookalikes; often serve the kit JS/CSS rather than the landing page itself
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0923 — Microsoft

```text
https://cdn-microsoft-data.com
```

- **Domain:** `cdn-microsoft-data.com`
- **Technique:** Newly registered fake-CDN lookalike used to host phishing kit resources and exfil endpoints
- **Detection:** Alert on script/XHR loads from cdn-microsoft* hosts on pages that also render a Microsoft logon form
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0924 — Microsoft Entra ID / Azure AD

```text
https://login-microsoft-virtual.com
```

- **Domain:** `login-microsoft-virtual.com`
- **Technique:** Newly registered login-prefixed lookalike mimicking Microsoft's auth hostname
- **Detection:** Highest-priority pattern: any apex beginning 'login-microsoft'; real endpoint is login.microsoftonline.com only
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0925 — Microsoft SharePoint Online

```text
https://sharepoint-microsoftonline.com
```

- **Domain:** `sharepoint-microsoftonline.com`
- **Technique:** Newly registered SharePoint/microsoftonline hybrid lookalike for shared-file sign-in lures
- **Detection:** Block any apex containing 'microsoftonline' that is not microsoftonline.com; SharePoint phish commonly pairs with .pdf/.htm attachment lures
- **Source:** phishunt.io newly-registered Microsoft domains — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-0926 — Microsoft Outlook/Hotmail

```text
https://hotmail-two.vercel.app
```

- **Domain:** `hotmail-two.vercel.app`
- **Technique:** Credential-harvest clone of Hotmail/Outlook sign-in hosted on free Vercel subdomain
- **Detection:** Alert on outbound HTTPS to *.vercel.app subdomains containing hotmail/outlook/office strings in proxy logs
- **Source:** OpenPhish via phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-11

### mfs-0927 — Microsoft 365

```text
https://csmgroup.blu-foods.com/login?method=signin&mode=secure
```

- **Domain:** `csmgroup.blu-foods.com`
- **Technique:** Compromised legitimate site hosting fake M365 /login page with signin/secure query params
- **Detection:** Hunt proxy logs for URI path /login with params method=signin&mode=secure on non-Microsoft hosts
- **Source:** OpenPhish via phishunt.io — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-11-11

### mfs-0928 — Microsoft 365 / Teams

```text
https://gpimmlgration.com
```

- **Domain:** `gpimmlgration.com`
- **Technique:** Device-code phishing — typosquatted domain + Google share-link redirect chain hides a Teams meeting-booking lure that relays a real Microsoft device code
- **Detection:** Hunt Entra sign-in logs for authenticationMethod 'Cmsi:Cmsi' from unmanaged devices, plus python-requests/node user agents on token requests
- **Source:** Huntress — https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
- **Status:** active
- **First seen:** 2026-11-12

### mfs-0933 — Microsoft SharePoint / Microsoft 365

```text
https://microsoftonline-sharepoint.online
```

- **Domain:** `microsoftonline-sharepoint.online`
- **Technique:** Typosquat apex combining microsoftonline + sharepoint on the .online TLD, fronting a fake SharePoint document-share sign-in
- **Detection:** Regex proxy logs for hostnames containing 'microsoftonline-' where the registrable domain is not microsoftonline.com
- **Source:** phishunt.io feed — https://phishunt.io/feed.txt
- **Status:** active
- **First seen:** 2026-11-02

### mfs-0953 — Microsoft 365 / SharePoint

```text
https://holytrip.com
```

- **Domain:** `holytrip.com`
- **Technique:** Compromised sender domain delivering SharePoint-themed PDF lures into the PhantomDOM Browser-in-the-Middle session-hijack chain
- **Detection:** Correlate inbound mail from holytrip.com with subsequent hits to entry.richmondmarketingsystems.org and IPs 31.57.184.0/24
- **Source:** ZeroBEC — https://zerobec.com/blog/phantomdom-browser-in-the-middle-microsoft-365
- **Status:** active
- **First seen:** 2026-11-05

### mfs-0954 — Microsoft Outlook / Office 365

```text
https://outlook-live365.github.io/paneldecontrol-365/
```

- **Domain:** `outlook-live365.github.io`
- **Technique:** Credential-harvest page hosted on GitHub Pages ('paneldecontrol-365' Spanish-language Outlook panel lure)
- **Detection:** Alert on *.github.io hosts whose org/repo name contains outlook/office/365/live; GitHub Pages is never a legitimate Microsoft auth origin
- **Source:** OpenPhish / Google Safe Browsing (via phishunt) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-15

### mfs-0955 — Microsoft 365

```text
https://hawkinsinc.microsoft-alerts.org
```

- **Domain:** `hawkinsinc.microsoft-alerts.org`
- **Technique:** Targeted subdomain-per-victim phishing (victim org name prefixed to attacker-owned 'microsoft-alerts' domain)
- **Detection:** Hunt for DNS/proxy requests where your own company name appears as a label on a non-Microsoft registrable domain containing 'microsoft'
- **Source:** Google Safe Browsing (via phishunt) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-14

### mfs-0956 — Microsoft 365 / Exchange Online

```text
https://reallifeaccounting.com/themelist0.html
```

- **Domain:** `reallifeaccounting.com`
- **Technique:** Final credential-harvest landing for the Nov 12 M365 outage 'held messages will be deleted in 24h' lure (incident EX1550543)
- **Detection:** Proxy-hunt for /themelist0.html and for any HTTP referer chain from SendGrid click-tracking to a non-Microsoft host serving an M365 sign-in form
- **Source:** Microsoft Threat Intelligence / Guardz — https://guardz.com/blog/microsoft-365-phishing-wave/
- **Status:** active
- **First seen:** 2026-11-13

### mfs-0957 — Microsoft 365

```text
https://mivorantul.com
```

- **Domain:** `mivorantul.com`
- **Technique:** Intermediate redirect host in the M365-outage credential phishing chain (Cloudflare-fronted 104.21.61.38 / 172.67.205.201)
- **Detection:** Block/alert on newly-registered Cloudflare-fronted domains appearing mid-chain between SendGrid click tracking and an M365 logon form
- **Source:** Guardz — https://guardz.com/blog/microsoft-365-phishing-wave/
- **Status:** active
- **First seen:** 2026-11-13

### mfs-0958 — Microsoft 365 / Exchange Online

```text
https://url7489.newbooker.com/ls/click
```

- **Domain:** `url7489.newbooker.com`
- **Technique:** Branded SendGrid click-tracking open-redirect fronting the outage-themed M365 phishing landing page
- **Detection:** Flag mail containing /ls/click?upn= or /wf/open?upn= on branded SendGrid CNAMEs from senders claiming to be 'Service Health' or 'Mail-Restore-Auth'; SendGrid account ID 118254266
- **Source:** Mimecast — https://www.mimecast.com/blog/attackers-exploit-the-microsoft-365-outage-with-fake-held-messages-lures/
- **Status:** active
- **First seen:** 2026-11-13

### mfs-0959 — Microsoft 365 / Exchange Online

```text
https://u118254266.ct.sendgrid.net/ls/click
```

- **Domain:** `u118254266.ct.sendgrid.net`
- **Technique:** Default SendGrid click-tracking redirect used in the same 'Outage - <6 chars>' / 'Restore messages' campaign
- **Detection:** Detonate (don't just parse) SendGrid ct.sendgrid.net links — the destination is encrypted in the upn parameter; pivot on account ID 118254266
- **Source:** Mimecast — https://www.mimecast.com/blog/attackers-exploit-the-microsoft-365-outage-with-fake-held-messages-lures/
- **Status:** active
- **First seen:** 2026-11-13

### mfs-0960 — Microsoft 365

```text
https://outagerestored.sbs/topics_pxyk/themelist0.html
```

- **Domain:** `outagerestored.sbs`
- **Technique:** Credential-phishing landing page behind a fake 'Microsoft 365 service health / outage restored' lure citing real incident EX1550543
- **Detection:** Alert on any outbound HTTP to *.sbs hosts with URI path matching /topics_*/themelist0.html; hunt mail for subjects 'Outage – <token>' or 'Restore — 4 messages'
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0961 — Microsoft 365

```text
https://outagefixed.sbs
```

- **Domain:** `outagefixed.sbs`
- **Technique:** Sibling landing domain in the same M365-outage credential-phishing kit (themelist0.html pattern)
- **Detection:** Block newly registered .sbs domains containing 'outage'; correlate first-seen DNS with mail click events referencing EX1550543
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0962 — Microsoft 365

```text
https://moments-notice.com
```

- **Domain:** `moments-notice.com`
- **Technique:** Sender/lure domain impersonating Microsoft 365 Service Health notifications
- **Detection:** Hunt message trace for P1/P2 sender domain moments-notice.com with display names ending 'Outage Notification' or 'Service Health'
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0963 — Microsoft 365

```text
https://em4493.moments-notice.com
```

- **Domain:** `em4493.moments-notice.com`
- **Technique:** ESP click-tracking subdomain redirecting to the fake Microsoft sign-in page
- **Detection:** Flag em####.* tracking subdomains on non-corporate sending domains in proxy logs
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0964 — Microsoft 365

```text
https://planetmaison.com
```

- **Domain:** `planetmaison.com`
- **Technique:** Compromised/abused sender domain for the Microsoft 365 outage credential-phishing wave
- **Detection:** Block at mail gateway and search for inbound mail citing incident ID EX1550543
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0965 — Microsoft 365

```text
https://em.newbooker.com
```

- **Domain:** `em.newbooker.com`
- **Technique:** Open-redirect / click-tracking hop in the Microsoft 365 outage phishing chain
- **Detection:** Proxy rule: any newbooker.com subdomain request following an inbound 'Outage' email click
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0966 — Microsoft 365

```text
https://url.newbooker.com
```

- **Domain:** `url.newbooker.com`
- **Technique:** Redirector hostname delivering victims to the fake Microsoft credential page
- **Detection:** Match URL hosts url*.newbooker.com; recipient-specific paths under /ls/click
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0967 — Microsoft 365

```text
https://u113727626.ct.sendgrid.net/ls/click
```

- **Domain:** `u113727626.ct.sendgrid.net`
- **Technique:** Abused SendGrid click-tracker fronting the Microsoft 365 outage credential-harvest page
- **Detection:** Hunt ct.sendgrid.net /ls/click events whose downstream host is reallifeaccounting.com or *.sbs
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0968 — Microsoft 365

```text
https://u118250677.ct.sendgrid.net/ls/click
```

- **Domain:** `u118250677.ct.sendgrid.net`
- **Technique:** Abused SendGrid click-tracker in the same Microsoft 365 service-health lure campaign
- **Detection:** Alert on SendGrid subuser IDs u1182506xx/u1137276xx appearing in inbound Microsoft-branded mail
- **Source:** Microsoft Threat Intelligence — https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/
- **Status:** active
- **First seen:** 2026-11-16

### mfs-0969 — Microsoft OneDrive / Microsoft 365

```text
https://domain.onedrive-live-shared-folder-attachment-microsoft365.com
```

- **Domain:** `domain.onedrive-live-shared-folder-attachment-microsoft365.com`
- **Technique:** Long keyword-stuffed lookalike domain hosting a fake OneDrive shared-file sign-in
- **Detection:** Regex newly registered domains concatenating 3+ of onedrive|live|shared|attachment|microsoft365
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0970 — Microsoft 365 / Azure AD

```text
https://www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site
```

- **Domain:** `www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site`
- **Technique:** Wildcard cPanel subdomain sprawl spoofing 'login.microsoftonline' billing-verification
- **Detection:** Block *.cpanel.site and alert on FQDNs containing 'microsoftonline-' with an embedded dashed IPv4 label
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0971 — Microsoft Outlook / Office 365

```text
http://login-outlook365.yzz.me
```

- **Domain:** `login-outlook365.yzz.me`
- **Technique:** Free dynamic-DNS host serving a cloned Outlook 365 sign-in
- **Detection:** Deny-list *.yzz.me; flag any hostname combining login+outlook365 on free DDNS zones
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0972 — Microsoft 365

```text
https://notifications.microsoft-ssl.com
```

- **Domain:** `notifications.microsoft-ssl.com`
- **Technique:** Typosquat domain posing as Microsoft security notification portal
- **Detection:** Hunt for 'microsoft-' prefixed second-level domains not in Microsoft's published domain list
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0973 — Microsoft Word / Office

```text
https://microsoftwordob.blogspot.com
```

- **Domain:** `microsoftwordob.blogspot.com`
- **Technique:** Blogspot-hosted fake Word document gateway leading to credential prompt
- **Detection:** Alert on *.blogspot.com pages whose title or path contains microsoft/word/office
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0974 — Microsoft Outlook

```text
https://plugins.sugar-outlook.com
```

- **Domain:** `plugins.sugar-outlook.com`
- **Technique:** Lookalike 'Outlook plugin' domain harvesting mailbox credentials
- **Detection:** Flag any non-Microsoft domain containing the token 'outlook' serving an auth form
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0975 — Microsoft 365

```text
https://microsoft365updates.com
```

- **Domain:** `microsoft365updates.com`
- **Technique:** Brand-impersonating 'update required' domain with fake M365 sign-in
- **Detection:** Newly observed domain monitoring on microsoft365* registrations; block at DNS
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0976 — Microsoft Outlook

```text
http://outlookmail.social
```

- **Domain:** `outlookmail.social`
- **Technique:** Typosquat on a cheap TLD hosting an Outlook webmail credential form
- **Detection:** Monitor .social/.sbs/.cfd registrations containing outlook|hotmail|m365
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0977 — Office 365

```text
http://office365licensingsupport.com
```

- **Domain:** `office365licensingsupport.com`
- **Technique:** Fake 'licensing support' portal collecting Office 365 credentials
- **Detection:** Alert on domains pairing office365 with support|licensing|billing keywords
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0978 — Microsoft 365

```text
http://microsoft365businessbasic.com
```

- **Domain:** `microsoft365businessbasic.com`
- **Technique:** SKU-named lookalike domain presenting a Microsoft 365 sign-in
- **Detection:** Hunt DNS for Microsoft product-SKU strings (businessbasic, e3, e5) in non-Microsoft domains
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0979 — Microsoft

```text
http://microsoft.updata.net.cn
```

- **Domain:** `microsoft.updata.net.cn`
- **Technique:** Subdomain abuse placing 'microsoft' as the left-most label on an unrelated CN domain
- **Detection:** Detect 'microsoft' as a subdomain label where the registrable domain is not microsoft.com
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0980 — Microsoft OneDrive

```text
https://onedrive.at-us.therelayservice.com/matpwp#/main?type=onedrive&locale=en&token=klb1x-bsfowhfwldwy5w5kex8sqynzrdesvfmnxmjl0tdf7uku8us441ssdv8qxwab7r07sx8d2tcaaxbilw7jrzwi1bt5g3m5qzpqncstyknfwj-yqfe_r7n9a3fu-ucws29093snwgphbneuqsxk8mdo1puqplqq_lyyy-z2vqt0erqcmg8tcawlfl4sskggccbqduptoyfosujteijqvlgjpzlcwk0wzrnqxxdxcdnwju5qyv2u4bj3idzgs8v6qa5yn4seek0heypiiacbhbz-jsqmkneijig233aier9rnsfanl5bt7eowf4952rktiz7odbtltsmxsfazcm3ga1xvespeobe4utzckdaigmdsculmol47bkalfeo3zqnkpb9hw-0acrojr0rpyclysnuwlrdsj3cwj5fljekfatvnxgqf6t6guofe50es9j4ljrt51cmwecxfrx7gnrdtg4vqsf_loqemh0n9qs_6pgwf78nhmzq2uzw-h3syvcvq9ymx-socacp8xhredrbz2z64w4xkxwty3fqjcnrfittqfgpdtnzmyg77ykywog3xcnqzclem2_oylu4f8ynj210a8hcdlwhk_kfpo-l-rvhhjwr8rvlblvvkztoo5nswd6zvqyiyh6c14wlbgmps9-4hbixryj-niycq2ngj7cha9mbmdeuln-4mx3i54
```

- **Domain:** `onedrive.at-us.therelayservice.com`
- **Technique:** Victim-specific tokenized OneDrive share lure on a SPA phishing kit (hash-routed /matpwp#/main)
- **Detection:** Proxy rule for URI fragment '#/main?type=onedrive' and very long single-use token query strings
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0981 — Microsoft Outlook

```text
https://outlook.verifytoken.com/s/63bzgfsvbwsfcdx7y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a
```

- **Domain:** `outlook.verifytoken.com`
- **Technique:** Per-recipient Outlook 'verify your token' credential page on shared kit infrastructure
- **Detection:** Hunt URI pattern /s/<18-char>/<6-hex>/<uuid> across any host; pivot on the shared path 63bzgfsvbwsfcdx7y9
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0982 — Microsoft Outlook

```text
https://outlook.webaccess-alert.com/s/63bzgfsvbwsfcdx7y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a
```

- **Domain:** `outlook.webaccess-alert.com`
- **Technique:** Second host reusing the identical kit path — 'outlook.' subdomain on an alert-themed lookalike
- **Detection:** Correlate hosts sharing the path /s/63bzgfsvbwsfcdx7y9/584dd8/ to enumerate the actor's domain pool
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0983 — Microsoft

```text
https://microsoftjk.eu.org
```

- **Domain:** `microsoftjk.eu.org`
- **Technique:** Free eu.org delegation hosting a Microsoft account sign-in clone
- **Detection:** Block *.eu.org registrations containing brand tokens; low-reputation free-zone policy
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0984 — Office 365

```text
https://office365.rricrosoft-offices.org/i/df3667320560f4a8a9918ef9f3f4c4383
```

- **Domain:** `office365.rricrosoft-offices.org`
- **Technique:** Homoglyph typosquat ('rri' for 'm') with /i/<32-hex> victim-ID credential page
- **Detection:** Detect rn/rri/vv homoglyph substitutions of 'microsoft'; alert on URI pattern /i/[a-f0-9]{32,33}
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0985 — Microsoft

```text
https://security.email-microsoft.com/diyc_smavt1av3ltaq
```

- **Domain:** `security.email-microsoft.com`
- **Technique:** Fake Microsoft security-alert portal on an 'email-microsoft' lookalike domain
- **Detection:** Flag FQDNs where 'microsoft' is a suffix label of a non-Microsoft registrable domain
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0986 — Office 365

```text
https://office365.internal-alerts.com/i/d5b9af0d256f14c03ab8396a78d3687bf
```

- **Domain:** `office365.internal-alerts.com`
- **Technique:** Same /i/<hex> kit as rricrosoft-offices.org — 'office365.' subdomain on alert-themed domain
- **Detection:** Pivot on shared kit URI /i/[a-f0-9]{33} to cluster office365.* subdomains across new domains
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0987 — Microsoft Live / Outlook

```text
http://reactivar-micr osoft-live.iceiy.com
```

- **Domain:** `reactivar-micr osoft-live.iceiy.com`
- **Technique:** Spanish-language 'reactivate your account' lure on free iceiy.com hosting
- **Detection:** Block *.iceiy.com; hunt Spanish keywords reactivar|verificar|cuenta combined with microsoft|live
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0988 — Microsoft 365

```text
https://microsoft.citrix-sharing.com
```

- **Domain:** `microsoft.citrix-sharing.com`
- **Technique:** 'microsoft' subdomain on a Citrix-themed file-share lookalike leading to an M365 credential prompt
- **Detection:** Alert on brand-crossover domains (microsoft label under citrix/dropbox/docusign-themed domains)
- **Source:** Phishunt / OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0989 — Microsoft 365

```text
https://microsoft-alpha.vercel.app
```

- **Domain:** `microsoft-alpha.vercel.app`
- **Technique:** Vercel-hosted static clone of the Microsoft sign-in page
- **Detection:** Block *.vercel.app subdomains containing microsoft|outlook|onedrive|office; monitor cert transparency
- **Source:** OpenPhish — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0990 — Microsoft 365

```text
https://m.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site
```

- **Domain:** `m.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site`
- **Technique:** Deceptive-subdomain typosquat on abused cPanel shared hosting (IP-named parent domain) serving a cloned Entra ID sign-in page
- **Detection:** Alert on DNS/proxy requests to any FQDN containing 'microsoftonline-' plus '.cpanel.site'; the dash-separated-IP label is a reliable pivot
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0991 — Microsoft 365

```text
https://www.m.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site
```

- **Domain:** `www.m.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site`
- **Technique:** Wildcard-subdomain typosquat variant of the same cPanel kit (repeated www./m. labels to pad the hostname)
- **Detection:** Flag hostnames with 4+ labels before a 'microsoftonline-*' string, or repeated 'www.' labels in one FQDN
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0992 — Microsoft 365 / Outlook Web Access

```text
https://webmail.login-microsoft-update-billing-online-secure-mainapp.20-14-89-105.cpanel.site
```

- **Domain:** `webmail.login-microsoft-update-billing-online-secure-mainapp.20-14-89-105.cpanel.site`
- **Technique:** Billing-update lure typosquat on cPanel shared hosting, 'webmail.' label to look like OWA
- **Detection:** Block *.cpanel.site outright if unused; otherwise hunt 'login-microsoft-update-billing' in TLS SNI/HTTP Host headers
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0993 — Microsoft 365

```text
https://cpanel.login-microsoft-update-billing-online-secure-mainapp.20-14-89-105.cpanel.site
```

- **Domain:** `cpanel.login-microsoft-update-billing-online-secure-mainapp.20-14-89-105.cpanel.site`
- **Technique:** Same billing-update cPanel kit, 'cpanel.' subdomain variant
- **Detection:** Pivot on the shared parent 'login-microsoft-update-billing-online-secure-mainapp' to enumerate sibling subdomains
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0994 — Microsoft 365

```text
https://www.www.www.login.microsoftonline-billing-verification-secured-help.8-219-97-148.cpanel.site
```

- **Domain:** `www.www.www.login.microsoftonline-billing-verification-secured-help.8-219-97-148.cpanel.site`
- **Technique:** Typosquat credential harvester; triple 'www.' padding pushes the real registrable domain off-screen on mobile
- **Detection:** Regex on hostname for '(www\.){2,}' — legitimate Microsoft hosts never repeat the www label
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0995 — Microsoft 365

```text
https://aflryvbz.microsoftonline-billing-verification-secured-help.52-234-33-034.cpanel.site
```

- **Domain:** `aflryvbz.microsoftonline-billing-verification-secured-help.52-234-33-034.cpanel.site`
- **Technique:** Random 8-char DGA-style subdomain per victim on the cPanel billing-verification kit
- **Detection:** Hunt 8-character all-lowercase-consonant subdomain labels preceding 'microsoftonline-billing-verification'
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0996 — Microsoft 365

```text
https://microsoftonline-billing-verification-secured-help.52-234-33-034.cpanel.site
```

- **Domain:** `microsoftonline-billing-verification-secured-help.52-234-33-034.cpanel.site`
- **Technique:** Bare apex of the billing-verification cPanel phishing cluster (new 52-234-33-034 node)
- **Detection:** Block the full parent domain, not just observed subdomains — the kit resolves arbitrary wildcard hosts
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0997 — Microsoft 365

```text
https://rgnmsfve.mgsfpgkn.zyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site
```

- **Domain:** `rgnmsfve.mgsfpgkn.zyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site`
- **Technique:** Multi-level random-label typosquat on the DigitalOcean-hosted (161.35.102.243) cPanel kit node
- **Detection:** Count labels: >6 DNS labels on a host containing 'microsoftonline' is almost always this kit
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0998 — Microsoft 365

```text
https://www.login.microsoftonline-billing-verification-secured-help.03-129-34-049.cpanel.site
```

- **Domain:** `www.login.microsoftonline-billing-verification-secured-help.03-129-34-049.cpanel.site`
- **Technique:** Typosquat on new cPanel node using zero-padded octets (03-129-34-049) to evade IP-pattern IOC matching
- **Detection:** Normalize zero-padded octets in dash-IP hostnames before matching your existing IOC list, or you will miss these
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-0999 — Microsoft 365

```text
https://www.cbndbysw.login.microsoftonline-billing-verification-secured-help.03-129-34-049.cpanel.site
```

- **Domain:** `www.cbndbysw.login.microsoftonline-billing-verification-secured-help.03-129-34-049.cpanel.site`
- **Technique:** Random-subdomain variant on the zero-padded 03-129-34-049 cPanel node
- **Detection:** Pivot passive DNS on the parent domain to pre-emptively block unseen random subdomains
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1000 — Microsoft 365

```text
https://www.vkpsourd.login.microsoftonline-billing-verification-secured-help.54-037-73-097.cpanel.site
```

- **Domain:** `www.vkpsourd.login.microsoftonline-billing-verification-secured-help.54-037-73-097.cpanel.site`
- **Technique:** Typosquat credential harvester on AWS-hosted (54.37.73.97) cPanel node, zero-padded octets
- **Detection:** Hunt HTTP Host headers matching 'microsoftonline-billing' regardless of subdomain entropy
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1001 — Microsoft 365

```text
https://www.wthpqpte.login.microsoftonline-billing-verification-secured-help.54-037-73-097.cpanel.site
```

- **Domain:** `www.wthpqpte.login.microsoftonline-billing-verification-secured-help.54-037-73-097.cpanel.site`
- **Technique:** Sibling random-subdomain variant on the same 54-037-73-097 cPanel node
- **Detection:** One blocklist entry on the parent domain covers all siblings; monitor new cert issuance via crt.sh for the parent
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1002 — Microsoft 365

```text
https://www.gttgvoej.microsoftonline-billing-verification-secured-help.134-209-251-140.cpanel.site
```

- **Domain:** `www.gttgvoej.microsoftonline-billing-verification-secured-help.134-209-251-140.cpanel.site`
- **Technique:** Typosquat harvester on DigitalOcean node 134.209.251.140, no 'login.' label (shorter variant)
- **Detection:** Do not require the 'login.' label when matching this cluster — some nodes omit it
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1003 — Microsoft 365

```text
https://www.login.microsoftonline-billing-verification-secured-help.167-71-169-104.cpanel.site
```

- **Domain:** `www.login.microsoftonline-billing-verification-secured-help.167-71-169-104.cpanel.site`
- **Technique:** Typosquat harvester on new DigitalOcean node 167.71.169.104
- **Detection:** Add ASN-level awareness: this cluster rotates across DigitalOcean/Azure/OVH IP-named cPanel hosts hourly
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1004 — Microsoft account (Live / MSA)

```text
https://account.microsoft.signin.resetting.password.21512121.dogsitters.ie
```

- **Domain:** `account.microsoft.signin.resetting.password.21512121.dogsitters.ie`
- **Technique:** Subdomain-path spoofing on a compromised legitimate .ie domain — brand words placed entirely in DNS labels
- **Detection:** Alert when 'account.microsoft' or 'signin' appear as DNS labels under a non-Microsoft registrable domain
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1005 — Microsoft 365 (passwordless / Entra ID)

```text
http://admin.foroshgahma.com/rfp/proposal/shared/microsoft_passwordless_1787664630667.html
```

- **Domain:** `admin.foroshgahma.com`
- **Technique:** Static HTML credential-harvest page on a compromised host, RFP/proposal-sharing lure, epoch-ms filename
- **Detection:** Hunt web proxy logs for URLs matching 'microsoft_passwordless_[0-9]{13}\.html' and for /rfp/proposal/shared/ paths on unfamiliar hosts
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1006 — Microsoft 365

```text
https://objectstorage.us-phoenix-1.oraclecloud.com/n/axganqadk0hk/b/bucket-20261109-1305/o/index1880353.htm
```

- **Domain:** `objectstorage.us-phoenix-1.oraclecloud.com`
- **Technique:** Microsoft 365 outage (incident EX1550543) lure — credential page hosted in an attacker-controlled Oracle Cloud object-storage bucket, reached via SendGrid click-tracking redirect
- **Detection:** Alert on Oracle Cloud objectstorage URLs ending in .htm/.html from email links; pivot on bucket namespace 'axganqadk0hk' and bucket name pattern 'bucket-YYYYMMDD-HHMM'
- **Source:** Cofense Intelligence (Flash Alert ATR 426633) — https://cofense.com/blog/flash-alert-weaponizing-the-november-2026-microsoft-outage
- **Status:** active
- **First seen:** 2026-11-16

### mfs-1007 — Microsoft 365 / Entra ID

```text
https://microwindow-e9fvg7ahe0cxf6a6.z02.azurefd.net
```

- **Domain:** `microwindow-e9fvg7ahe0cxf6a6.z02.azurefd.net`
- **Technique:** Sneaky2FA AiTM reverse-proxy sign-in page hosted on Azure Front Door, reached via abused ActiveCampaign tracking links; steals post-MFA session cookies
- **Detection:** Azure Front Door default hostnames (*.azurefd.net) rendering a Microsoft sign-in form are never legitimate — alert on 'microsoft'-themed strings in *.azurefd.net SNI and on Entra sign-ins where one session ID is reused from multiple ASNs
- **Source:** KnowBe4 ThreatLabs — https://x.com/Kb4Threatlabs/status/2115375353158136270
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1008 — Microsoft 365 / Entra ID

```text
https://xn--smarktt-y0a.net/connect/
```

- **Domain:** `xn--smarktt-y0a.net`
- **Technique:** IDN/punycode homoglyph domain hosting a Sneaky2FA AiTM fake Microsoft login at /connect/
- **Detection:** Flag any xn-- (punycode) hostname serving a Microsoft-branded login; block xn--* domains not on an allowlist at the egress proxy
- **Source:** KnowBe4 ThreatLabs — https://x.com/Kb4Threatlabs/status/2115375353158136270
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1009 — Microsoft 365 / Entra ID

```text
https://scontitech.emlnk9.com/lt.php
```

- **Domain:** `scontitech.emlnk9.com`
- **Technique:** Abused ActiveCampaign email-marketing click-tracker used as the first hop redirecting to the Sneaky2FA fake Microsoft sign-in page
- **Detection:** Hunt inbound mail and proxy logs for '/lt.php' on *.emlnk*.com or *.activehosted.com tracker hosts; correlate with a Microsoft-branded landing page in the same session
- **Source:** KnowBe4 ThreatLabs — https://x.com/Kb4Threatlabs/status/2115375353158136270
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1010 — Microsoft 365 / Entra ID

```text
https://scontitech.activehosted.com/lt.php
```

- **Domain:** `scontitech.activehosted.com`
- **Technique:** Second abused ActiveCampaign tracking hostname for the same Sneaky2FA AiTM chain
- **Detection:** Pivot on the 'scontitech' account label across ActiveCampaign tracker domains; block both emlnk9.com and activehosted.com variants together
- **Source:** KnowBe4 ThreatLabs — https://x.com/Kb4Threatlabs/status/2115375353158136270
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1011 — Microsoft 365 / Entra ID

```text
https://polwanlo.vip
```

- **Domain:** `polwanlo.vip`
- **Technique:** First-hop attacker redirector in the 'Hidden Relay' OAuth device-code phishing chain that never displays the device code to the victim
- **Detection:** Treat .vip newly-registered domains in email links as high risk; alert on Entra ID device-code grants (client ID 29d9ed98-a469-4536-ade2-f981bc1d605e) following any external link click
- **Source:** KnowBe4 ThreatLabs — https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code
- **Status:** active
- **First seen:** 2026-11-12

### mfs-1012 — Microsoft 365 / Entra ID

```text
https://merlekw.workers.dev
```

- **Domain:** `merlekw.workers.dev`
- **Technique:** Cloudflare Worker campaign router in the Hidden Relay device-code kit; carries the campaign token in ?_k= and mints the victim transfer token
- **Detection:** Alert on *.workers.dev URLs containing a '?_k=' parameter; block default workers.dev hostnames at the proxy unless explicitly allowlisted
- **Source:** KnowBe4 ThreatLabs — https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code
- **Status:** active
- **First seen:** 2026-11-12

### mfs-1013 — Microsoft 365 / Entra ID

```text
https://maxjln.workers.dev
```

- **Domain:** `maxjln.workers.dev`
- **Technique:** Cloudflare Worker hosting the Turnstile anti-bot gate and the fake Microsoft sign-in kit page for the Hidden Relay device-code campaign
- **Detection:** Hunt for a Cloudflare Turnstile challenge immediately preceding a Microsoft-branded login on a *.workers.dev host
- **Source:** KnowBe4 ThreatLabs — https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code
- **Status:** active
- **First seen:** 2026-11-12

### mfs-1014 — Microsoft 365 / Entra ID

```text
https://c30d9e770432bc4-id-gate.bandgdruback1.workers.dev
```

- **Domain:** `c30d9e770432bc4-id-gate.bandgdruback1.workers.dev`
- **Technique:** Backend Worker serving the device-authorization endpoints (POST /api/device/start with X-Worker-Token header) that silently requests the code from Microsoft on the victim's behalf
- **Detection:** Alert on requests to '/api/device/start' or hostnames matching '[0-9a-f]{15}-id-gate'; hunt the X-Worker-Token header in proxy logs
- **Source:** KnowBe4 ThreatLabs — https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code
- **Status:** active
- **First seen:** 2026-11-12

### mfs-1015 — Microsoft 365 / Entra ID

```text
https://bandgdruback1.workers.dev/link/372b56d018b8cbc359b0819e402f11d5
```

- **Domain:** `bandgdruback1.workers.dev`
- **Technique:** Per-victim relay page URL in the Hidden Relay device-code kit (/link/ + 32 hex chars), auto-approving the device grant without showing the code
- **Detection:** Regex proxy logs for '/link/[0-9a-f]{32}' on *.workers.dev; also hunt session IDs matching 'ses_<unix_ms>_<8 hex>'
- **Source:** KnowBe4 ThreatLabs — https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code
- **Status:** active
- **First seen:** 2026-11-12

### mfs-1016 — Microsoft 365

```text
https://okmjoqzhle.klavontrix.com
```

- **Domain:** `okmjoqzhle.klavontrix.com`
- **Technique:** Multi-hop redirector in Microsoft 365 outage (EX1550543) lure chain leading to cloned Entra ID sign-in page
- **Detection:** Hunt EmailUrlInfo/UrlClickEvents for any *.klavontrix.com host; random 10-char lowercase subdomain + newly registered parent domain is the pattern
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1017 — Microsoft 365

```text
https://klavontrix.com
```

- **Domain:** `klavontrix.com`
- **Technique:** Redirect/phishing parent domain used in Exchange Online outage credential-harvest campaign
- **Detection:** Block the apex and all subdomains; alert on first-seen DNS resolution for domains registered <30 days referenced in outage-themed mail
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1018 — Microsoft 365

```text
https://uoowsdiftk.mivorantul.com
```

- **Domain:** `uoowsdiftk.mivorantul.com`
- **Technique:** Random-subdomain redirector hop between SendGrid click-tracking link and fake Microsoft sign-in page
- **Detection:** Regex on URL host ^[a-z]{10}\.[a-z]+\.com$ seen in UrlClickEvents within minutes of a mail whose subject starts "Outage -"
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1019 — Microsoft 365

```text
https://app.naturekojamibaramet.cyou/r/cloupriv/?token=
```

- **Domain:** `app.naturekojamibaramet.cyou`
- **Technique:** Tokenized per-recipient redirect (/r/cloupriv/?token=) fronting the Microsoft credential-harvest page
- **Detection:** Alert on outbound GET to any host with URI path /r/cloupriv/ or on .cyou TLD traffic from managed endpoints
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1020 — Microsoft 365

```text
https://naturekojamibaramet.cyou
```

- **Domain:** `naturekojamibaramet.cyou`
- **Technique:** Phishing apex domain (nonsense-word DGA-style label on cheap .cyou TLD) in outage-lure chain
- **Detection:** Baseline-block .cyou at the proxy; nonsense long single-label domains are near-zero legitimate business traffic
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1021 — Microsoft 365

```text
https://businessexperience.cfd/common?key=
```

- **Domain:** `businessexperience.cfd`
- **Technique:** Fake Microsoft /common sign-in endpoint with per-victim ?key= parameter (mimics Entra ID common tenant path)
- **Detection:** Hunt for non-Microsoft hosts serving a URI path of /common with a key= query string; .cfd TLD is a known phish-mail favorite
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1022 — Microsoft 365

```text
https://click.newbooker.com
```

- **Domain:** `click.newbooker.com`
- **Technique:** Attacker-controlled click-tracking redirector on a campaign sender domain (outage-restore lure)
- **Detection:** Block all *.newbooker.com; correlate UrlClickEvents against sender domains moments-notice.com / planetmaison.com / newbooker.com
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1023 — Microsoft 365

```text
https://em.planetmaison.com
```

- **Domain:** `em.planetmaison.com`
- **Technique:** Mail/link subdomain on attacker sender domain used to relay victims to the spoofed Microsoft 365 login
- **Detection:** Wildcard-block *.planetmaison.com; flag em.* and url<digits>.* subdomains on freshly registered sender domains
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1024 — Microsoft 365

```text
https://url2830.planetmaison.com
```

- **Domain:** `url2830.planetmaison.com`
- **Technique:** Numbered SendGrid-style click-tracking host redirecting to the Microsoft credential-harvest page
- **Detection:** Regex host ^url\d{3,5}\.[a-z]+\.com$ in EmailUrlInfo — same template as url7489.newbooker.com from the same campaign
- **Source:** Cyber Security News (Microsoft Threat Intelligence campaign reporting) — https://cybersecuritynews.com/hackers-impersonate-microsoft-exchange/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1025 — Microsoft 365 / Entra ID

```text
http://login.microsoftonline.rcm-portal.at
```

- **Domain:** `login.microsoftonline.rcm-portal.at`
- **Technique:** Subdomain-prefix typosquat — 'login.microsoftonline' placed as a subdomain label on an attacker-owned .at domain to fake the real sign-in host
- **Detection:** Alert on DNS/proxy requests where 'microsoftonline' appears in any label other than the registrable domain (i.e. not *.microsoftonline.com)
- **Source:** Phishunt (Microsoft tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1026 — Microsoft 365 / Entra ID

```text
http://login.microsoftonline.bamboohr.app
```

- **Domain:** `login.microsoftonline.bamboohr.app`
- **Technique:** Subdomain-prefix typosquat abusing a lookalike HR-SaaS domain (bamboohr.app) to host a fake Entra sign-in page
- **Detection:** Hunt proxy logs for hostnames matching 'login.microsoftonline.*' where the eTLD+1 is not microsoftonline.com; also flag HR/payroll-branded domains serving Microsoft login HTML
- **Source:** OpenPhish (via Phishunt) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1027 — Microsoft 365

```text
https://login.m-microsoft.com
```

- **Domain:** `login.m-microsoft.com`
- **Technique:** Typosquat / hyphen-insertion lookalike domain hosting a cloned Microsoft credential-harvesting login form
- **Detection:** Regex newly-registered domains for ^(m|rn|rnicro|micr0|m-)microsoft\. and correlate with Microsoft-branded favicon/logo hashes in urlscan
- **Source:** Phishunt (Microsoft tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1028 — Microsoft 365 / Copilot

```text
https://copilot.m365cloud-microsoft.com
```

- **Domain:** `copilot.m365cloud-microsoft.com`
- **Technique:** Copilot-themed lure on a 'm365cloud-microsoft' combosquat domain leading to a fake Microsoft sign-in page
- **Detection:** Block/alert on any non-Microsoft-owned domain containing both 'm365' or 'copilot' and 'microsoft'; watch for Copilot-branded doc-share lures
- **Source:** Phishunt (Microsoft tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1029 — Microsoft Outlook / Exchange Online

```text
https://outlookquarantinenotice.com
```

- **Domain:** `outlookquarantinenotice.com`
- **Technique:** Fake Exchange Online quarantine-digest notification driving victims to an Outlook credential-capture page
- **Detection:** Flag inbound mail whose quarantine-digest links do not resolve to quarantine@messaging.microsoft.com infrastructure; block 'outlook*quarantine*' domains
- **Source:** Phishunt (Microsoft tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1030 — Microsoft Hotmail / Live

```text
https://hotmail666.com
```

- **Domain:** `hotmail666.com`
- **Technique:** Brandjacked Hotmail apex domain fronting credential-harvesting subdomains (api./usdt.)
- **Detection:** Resolve and block the apex plus wildcard subdomains; alert on any 'hotmail'-containing domain not under hotmail.com/live.com
- **Source:** Phishunt (Microsoft tracker) — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1031 — Microsoft 365 / SharePoint

```text
https://9l2v3vupv5.synerghylnksloads.cfd/l/CqCFCeikrUA
```

- **Domain:** `9l2v3vupv5.synerghylnksloads.cfd`
- **Technique:** Device-code OAuth phishing — HTML/SVG attachment redirector to a verification gate and counterfeit SharePoint workspace that feeds the real login.microsoftonline.com/common/oauth2/deviceauth flow
- **Detection:** Alert on Entra ID sign-in logs with authenticationProtocol=deviceCode from unexpected clients/geo; block random-10-char subdomains on .cfd/.sbs
- **Source:** Hornetsecurity Threat Intelligence Lab — https://www.hornetsecurity.com/en/blog/microsoft-365-device-code-phishing/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1032 — Microsoft 365 / SharePoint

```text
https://tgg5rqrdcb.synerghylnksloads.cfd
```

- **Domain:** `tgg5rqrdcb.synerghylnksloads.cfd`
- **Technique:** Device-code OAuth phishing infrastructure (second host on the same .cfd lure domain)
- **Detection:** Pivot on the registrable domain synerghylnksloads.cfd and block wildcard; hunt HTML attachments with repeating-key XOR / substituted-Base64 fragments
- **Source:** Hornetsecurity Threat Intelligence Lab — https://www.hornetsecurity.com/en/blog/microsoft-365-device-code-phishing/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1033 — Microsoft 365 / SharePoint

```text
https://ngjedt0xrv.promtateusachorloadscorp.sbs
```

- **Domain:** `ngjedt0xrv.promtateusachorloadscorp.sbs`
- **Technique:** Payment-themed document lure host in the device-code OAuth phishing chain to Microsoft sign-in
- **Detection:** Block .sbs/.cfd newly-registered domains with random alphanumeric subdomains serving /l/<token> redirect paths
- **Source:** Hornetsecurity Threat Intelligence Lab — https://www.hornetsecurity.com/en/blog/microsoft-365-device-code-phishing/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1034 — Microsoft 365

```text
https://5txpm30dqe.krointechbillpaycheckingusalexingto.sbs
```

- **Domain:** `5txpm30dqe.krointechbillpaycheckingusalexingto.sbs`
- **Technique:** Billing/invoice-themed lure host in the same device-code phishing cluster targeting M365 token issuance
- **Detection:** Correlate mail-click telemetry to .sbs hosts followed within minutes by a deviceCode sign-in event for the same user
- **Source:** Hornetsecurity Threat Intelligence Lab — https://www.hornetsecurity.com/en/blog/microsoft-365-device-code-phishing/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1035 — Microsoft 365 / SharePoint

```text
https://base-hub-yw7q.p-xxorevv8.workers.dev/l/taaeR_gygko
```

- **Domain:** `base-hub-yw7q.p-xxorevv8.workers.dev`
- **Technique:** Cloudflare Workers-hosted redirector (payment-advice variant) into the Microsoft device-code consent flow
- **Detection:** Treat *.workers.dev with /l/<token> paths as high-risk redirectors; block unapproved workers.dev subdomains at the proxy
- **Source:** Hornetsecurity Threat Intelligence Lab — https://www.hornetsecurity.com/en/blog/microsoft-365-device-code-phishing/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1036 — Microsoft 365

```text
https://security-awareness.microsoft365.studio
```

- **Domain:** `security-awareness.microsoft365.studio`
- **Technique:** Brand-suffix lookalike domain on .studio TLD posing as a Microsoft 365 security-awareness portal to harvest credentials
- **Detection:** Alert on DNS/proxy requests to any registrable domain containing 'microsoft365' outside microsoft.com/microsoftonline.com; flag newly registered .studio/.site/.live TLDs with Microsoft brand strings
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1037 — Microsoft Outlook

```text
https://outlook-notifications.com
```

- **Domain:** `outlook-notifications.com`
- **Technique:** Typosquat/brand-impersonation domain mimicking Outlook mailbox notification alerts (quarantine/held-mail lure)
- **Detection:** Hunt mail URLs matching /outlook[-_.](notification|alert|quarantine|verify)/ in Defender for Office 365 UrlClickEvents; low-reputation domain with Outlook favicon
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1038 — Microsoft

```text
https://microsofth.com
```

- **Domain:** `microsofth.com`
- **Technique:** Typosquat apex domain (extra 'h' after microsoft) fronting a wildcard-subdomain Microsoft credential-phishing cluster
- **Detection:** Block the whole zone, not single hosts — alert on any DNS resolution for *.microsofth.com; detect Levenshtein distance 1 from 'microsoft.com' in egress SNI
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1039 — Microsoft Defender SmartScreen

```text
https://smartscreen.microsofth.com
```

- **Domain:** `smartscreen.microsofth.com`
- **Technique:** Typosquat subdomain abusing a Microsoft security-product name to make the phishing lure look like a safety warning
- **Detection:** Flag hostnames where a Microsoft product label (smartscreen/defender) is the subdomain of a non-Microsoft registrable domain
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1040 — Microsoft Rewards

```text
https://rewardsplatform.microsofth.com
```

- **Domain:** `rewardsplatform.microsofth.com`
- **Technique:** Typosquat subdomain using a Microsoft Rewards incentive lure to funnel victims to a Microsoft account sign-in
- **Detection:** Correlate 'rewards' + Microsoft brand token in hostname with first-seen-domain age under 30 days
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1041 — Microsoft

```text
https://random.microsofth.com
```

- **Domain:** `random.microsofth.com`
- **Technique:** Wildcard/catch-all subdomain on the microsofth.com typosquat cluster, indicating per-victim hostname generation
- **Detection:** Wildcard DNS on a brand typosquat is the tell — resolve two nonsense labels under the zone; identical A records confirm catch-all phishing infrastructure
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1042 — Microsoft

```text
https://mp.microsofth.com
```

- **Domain:** `mp.microsofth.com`
- **Technique:** Short-label subdomain on the microsofth.com typosquat cluster hosting Microsoft sign-in content
- **Detection:** Include in the *.microsofth.com zone block; alert on TLS certificates issued to microsofth.com in CT log monitoring
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1043 — Microsoft Learn

```text
https://learn.microsofth.com
```

- **Domain:** `learn.microsofth.com`
- **Technique:** Typosquat subdomain cloning the Microsoft Learn hostname pattern to lend legitimacy before a credential prompt
- **Detection:** Hunt for hostnames reusing real Microsoft subdomain labels (learn/docs/support) under non-Microsoft parent domains
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1044 — Microsoft

```text
https://hostmaster.microsofth.com
```

- **Domain:** `hostmaster.microsofth.com`
- **Technique:** Infrastructure-style subdomain on the microsofth.com typosquat cluster
- **Detection:** Enumerate CT logs and passive DNS for all microsofth.com subdomains and block the zone wholesale
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1045 — Microsoft Outlook

```text
https://email.microsofth.com
```

- **Domain:** `email.microsofth.com`
- **Technique:** Typosquat subdomain presenting a webmail/Outlook sign-in to harvest Microsoft 365 credentials
- **Detection:** Alert on webmail-themed subdomains ('email','mail','webmail','owa') under brand-typosquat parent domains
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1046 — Microsoft OneDrive

```text
https://packaging.onedrive.business
```

- **Domain:** `packaging.onedrive.business`
- **Technique:** Brand-as-domain abuse — 'onedrive' registered as the second-level label under .business to fake a OneDrive for Business file-share sign-in
- **Detection:** Flag any registrable domain whose second-level label is exactly a Microsoft product name (onedrive/sharepoint/office365) on a non-Microsoft TLD; OneDrive file-share lures should only resolve to *.sharepoint.com or onedrive.live.com
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1047 — Microsoft Entra ID

```text
https://login.microsoftonline.xrb.okx.mybluehost.me
```

- **Domain:** `login.microsoftonline.xrb.okx.mybluehost.me`
- **Technique:** Subdomain-prefix spoof placing 'login.microsoftonline' in front of a compromised/abused mybluehost.me shared-hosting domain
- **Detection:** Regex egress DNS/SNI for 'login\.microsoftonline' NOT followed by '\.com$' — the real host is only login.microsoftonline.com; also blanket-flag *.mybluehost.me in mail URLs
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1048 — Microsoft Entra ID

```text
https://mail.login.microsoftonline.xrb.okx.mybluehost.me
```

- **Domain:** `mail.login.microsoftonline.xrb.okx.mybluehost.me`
- **Technique:** Deep-nested subdomain spoof ('mail.login.microsoftonline.*') on abused mybluehost.me hosting, targeting Outlook/Exchange sign-in
- **Detection:** Count labels before the registrable domain — 5+ labels embedding Microsoft brand tokens on consumer shared hosting is near-exclusively phishing; block the full xrb.okx.mybluehost.me branch
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1049 — Microsoft 365

```text
http://microsoftsignin.azurewebsites.net/
```

- **Domain:** `microsoftsignin.azurewebsites.net`
- **Technique:** Credential-harvest sign-in clone hosted on abused Azure App Service (*.azurewebsites.net) so the page inherits a Microsoft-owned TLS cert and domain
- **Detection:** Alert on proxy/DNS traffic to *.azurewebsites.net hostnames containing microsoft/signin/login/m365 that are not in your own App Service inventory — legit tenants almost never sign in via azurewebsites.net
- **Source:** OpenPhish (public feed) — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1050 — Microsoft Outlook

```text
https://outlookmails.de
```

- **Domain:** `outlookmails.de`
- **Technique:** Typosquat/lookalike domain serving a fake Outlook webmail UI (urlscan title "mail.outlookmails.de - mail UI") for credential capture
- **Detection:** Hunt DNS/HTTP for *outlookmail*.<ccTLD> registrations and for autodiscover./autoconfig. subdomains on non-Microsoft apex domains — the actor stood both up to look like a real mail tenant
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1051 — Microsoft Outlook

```text
https://mail.outlookmails.de
```

- **Domain:** `mail.outlookmails.de`
- **Technique:** Fake Outlook webmail login host on the outlookmails.de lookalike apex
- **Detection:** Block the apex and all subdomains; flag Outlook-branded logon pages whose host does not end in outlook.com/office.com/microsoftonline.com
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1052 — Microsoft Outlook

```text
https://outlook-silk-nine.vercel.app
```

- **Domain:** `outlook-silk-nine.vercel.app`
- **Technique:** Free-PaaS-hosted Outlook sign-in clone on Vercel (disposable *.vercel.app subdomain, instant HTTPS)
- **Detection:** Alert on first-seen *.vercel.app / *.netlify.app / *.pages.dev hostnames whose label matches outlook|office|microsoft|onedrive|sharepoint|hotmail; these are near-100% phishing in enterprise traffic
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1053 — Microsoft 365 (billing/licensing lure)

```text
https://jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site
```

- **Domain:** `jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site`
- **Technique:** Deceptive-subdomain chain on a cPanel default hostname — random 8-char label + 'login.microsoftonline-billing-verification-secured-help' prefixed onto *.cpanel.site so the visible left-hand side reads as Microsoft
- **Detection:** Regex DNS/TLS SNI and proxy logs for hosts matching microsoftonline-[a-z-]+\..*\.cpanel\.site, and for any FQDN with >4 labels containing 'login.microsoftonline' that does not terminate in microsoftonline.com; CT-log monitor cpanel.site certs
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1054 — Microsoft 365 (billing/licensing lure)

```text
https://test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site
```

- **Domain:** `test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site`
- **Technique:** Staging/'test' sibling of the same cPanel deceptive-subdomain kit — same IP-named cpanel.site host, indicating an active kit under development
- **Detection:** Wildcard-block *.microsoftonline-billing-verification-secured-help.*.cpanel.site; treat 'test.' siblings on known phish hosts as pre-launch IOCs and pre-emptively blocklist the parent
- **Source:** Phishunt — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1055 — Microsoft Teams

```text
http://msteamsjoinmeetinginvite.online
```

- **Domain:** `msteamsjoinmeetinginvite.online`
- **Technique:** Teams meeting-invite typosquat used as a credential/consent lure landing page (bulk-registered .online cluster)
- **Detection:** Hunt newly-registered domains matching (ms)?teams.*(join|meeting|invite) on .online/.site/.cloud; Teams join links should only resolve to teams.microsoft.com or teams.live.com
- **Source:** TweetFeed (@patialavii on X) — https://x.com/patialavii/status/2123244865743909211
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1056 — Microsoft Teams

```text
http://msteamsjoinmeetinginvites.online
```

- **Domain:** `msteamsjoinmeetinginvites.online`
- **Technique:** Plural variant in the same bulk-registered Teams-invite typosquat cluster
- **Detection:** Pivot on the registrar/NS/IP of the msteams*.online cluster and blocklist the whole set, not just the reported FQDN
- **Source:** TweetFeed (@patialavii on X) — https://x.com/patialavii/status/2123244865743909211
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1057 — Microsoft Teams

```text
http://msteamsmeetings.online
```

- **Domain:** `msteamsmeetings.online`
- **Technique:** Teams-meeting typosquat in the same cluster; urlscan shows it currently serving a registrar default page, i.e. staged infrastructure not yet weaponised
- **Detection:** Blocklist on registration rather than on content — parked lookalikes in an active cluster flip to live phish pages within days; monitor for first non-parked HTTP response
- **Source:** TweetFeed (@patialavii on X) — https://x.com/patialavii/status/2123244865743909211
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1058 — Microsoft Teams / Copilot

```text
http://msteams-ai.com
```

- **Domain:** `msteams-ai.com`
- **Technique:** AI-themed Teams lookalike domain (Teams+Copilot branding) used for credential phishing lures
- **Detection:** Flag domains combining a Microsoft product token (teams|copilot|m365|office) with ai|assistant|chat — the 2026 lure theme; none are Microsoft-owned
- **Source:** TweetFeed (@Malwarehunterr on X) — https://x.com/Malwarehunterr/status/2119505228802465857
- **Status:** active
- **First seen:** 2026-11-08

### mfs-1059 — Microsoft 365

```text
https://accounts.billingmicrosloft365.site
```

- **Domain:** `accounts.billingmicrosloft365.site`
- **Technique:** Homoglyph/letter-insertion typosquat ('micros-l-oft') on an 'accounts.' subdomain with a billing/subscription-renewal lure
- **Detection:** Run Levenshtein/confusable checks for microsoft within distance 2 (microsloft, rnicrosoft, micros0ft, microsofl) across new-domain feeds and CT logs; alert on 'accounts.'/'login.' subdomains of such hits
- **Source:** TweetFeed (@masaomi346 on X) — https://x.com/masaomi346/status/2118918043778834726
- **Status:** active
- **First seen:** 2026-11-07

### mfs-1060 — Microsoft 365 / Entra ID

```text
https://login-msftportal.com/captcha.html?email=phishing@live.com
```

- **Domain:** `login-msftportal.com`
- **Technique:** CAPTCHA-gated AiTM: a bot-check interstitial (captcha.html) filters sandboxes before relaying the victim to a live Entra ID sign-in, with the target address pre-filled via the ?email= parameter
- **Detection:** Alert on any URL carrying ?email=<corporate address> to a non-Microsoft host, and on 'captcha.html' paths preceding a Microsoft-branded logon; in Entra sign-in logs hunt successful auths whose user agent/ASN differs from the session's token-replay follow-up
- **Source:** TweetFeed (@crimeonprem on X) — https://x.com/crimeonprem/status/2119134622844100942
- **Status:** active
- **First seen:** 2026-11-07

### mfs-1061 — Microsoft Outlook

```text
https://download-outlook.com
```

- **Domain:** `download-outlook.com`
- **Technique:** Newly registered combosquat domain hosting fake Outlook sign-in / client download lure
- **Detection:** Alert on newly-observed domains matching /(^|[.-])(download|get|install)-?outlook/ in proxy logs
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1062 — Microsoft 365

```text
https://mylogin-microsoftonline.com
```

- **Domain:** `mylogin-microsoftonline.com`
- **Technique:** Typosquat of login.microsoftonline.com used as credential-harvesting portal
- **Detection:** Hunt HTTP POSTs to any registrable domain containing 'microsoftonline' that is not microsoftonline.com
- **Source:** phishunt.io — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1063 — OneDrive / SharePoint

```text
https://onedrivesharepointopenspacepresentationdocuments832778328.autos
```

- **Domain:** `onedrivesharepointopenspacepresentationdocuments832778328.autos`
- **Technique:** Long-string keyword-stuffed lure domain on cheap .autos TLD impersonating a shared document
- **Detection:** Flag DNS resolutions to hosts >50 chars containing both 'onedrive' and 'sharepoint'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1064 — Microsoft OneDrive

```text
https://onedrive-document-share.com
```

- **Domain:** `onedrive-document-share.com`
- **Technique:** Combosquat domain serving fake 'shared document' OneDrive sign-in page
- **Detection:** Block newly registered domains combining 'onedrive' with document/share keywords
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1065 — Microsoft Teams

```text
https://microsofteamsetup.top
```

- **Domain:** `microsofteamsetup.top`
- **Technique:** Typosquat (microsoft+teams/team-setup) on .top TLD for Teams meeting-join credential lure
- **Detection:** Hunt .top/.live/.shop registrations containing 'microsoft' + 'team'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1066 — Microsoft 365

```text
https://microsoft365-app.com
```

- **Domain:** `microsoft365-app.com`
- **Technique:** Brand-impersonation domain posing as an official Microsoft 365 app portal
- **Detection:** Deny-list non-Microsoft registrable domains containing 'microsoft365'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1067 — Microsoft 365

```text
https://microsoft-365-user-auth-2-access-private-files.live
```

- **Domain:** `microsoft-365-user-auth-2-access-private-files.live`
- **Technique:** Keyword-stuffed auth-themed lure domain on .live TLD prompting M365 sign-in for 'private files'
- **Detection:** Alert on hostnames containing 'auth' plus 'microsoft' on .live/.autos/.cfd TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1068 — Microsoft Outlook

```text
https://outlooks.life
```

- **Domain:** `outlooks.life`
- **Technique:** Pluralized typosquat of Outlook on novelty .life TLD
- **Detection:** Hunt pluralized brand typosquats (outlooks, microsofts, hotmails) across all TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1069 — Microsoft Outlook

```text
https://outlookmc.com
```

- **Domain:** `outlookmc.com`
- **Technique:** Short-suffix typosquat domain used for Outlook webmail credential capture
- **Detection:** Flag 2-letter-suffix brand variants (outlookmc, hotmailmc) registered within 30 days
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1070 — Microsoft Outlook

```text
https://outlook-maill.com
```

- **Domain:** `outlook-maill.com`
- **Technique:** Doubled-letter typosquat ('maill') for Outlook mail sign-in page
- **Detection:** Regex proxy logs for repeated-character brand misspellings: mai?ll, hotmaill, outlookk
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1071 — Microsoft Outlook

```text
https://out1ook.vip
```

- **Domain:** `out1ook.vip`
- **Technique:** Homoglyph typosquat substituting digit 1 for letter l in 'outlook'
- **Detection:** Normalize 1/l and 0/o in hostnames before brand matching; alert on digit-substituted brands
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1072 — Microsoft OneDrive

```text
https://onedrivedoc.net
```

- **Domain:** `onedrivedoc.net`
- **Technique:** Combosquat domain hosting fake OneDrive document-preview credential page
- **Detection:** Block 'onedrive'+'doc' domain combinations not owned by Microsoft
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1073 — Microsoft Office 365

```text
https://office365msangelacmcmahonsolicitormicrosoft.com
```

- **Domain:** `office365msangelacmcmahonsolicitormicrosoft.com`
- **Technique:** Victim-specific combosquat embedding a target law firm's name with Office 365 branding
- **Detection:** Alert when a newly registered domain contains both your organization name and 'office365' or 'microsoft'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1074 — Microsoft

```text
https://microsoftrnail.com
```

- **Domain:** `microsoftrnail.com`
- **Technique:** Homoglyph typosquat using 'rn' to mimic 'm' in microsoftmail
- **Detection:** Hunt rn→m and vv→w homoglyph substitutions in domains containing 'microsoft'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1075 — Microsoft 365

```text
https://microsoftpdf.com
```

- **Domain:** `microsoftpdf.com`
- **Technique:** Brand combosquat used for fake PDF/document-viewer sign-in prompts
- **Detection:** Flag document-keyword + 'microsoft' domains referred from email link clicks
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1076 — Microsoft 365

```text
https://microsoftonline.dog
```

- **Domain:** `microsoftonline.dog`
- **Technique:** Exact brand string 'microsoftonline' on an unrelated novelty TLD
- **Detection:** Block the exact SLD 'microsoftonline' on any TLD other than .com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1077 — Microsoft

```text
https://microsoft72000.com
```

- **Domain:** `microsoft72000.com`
- **Technique:** Numeric-suffix brand impersonation domain (randomized registration pattern)
- **Detection:** Hunt 'microsoft' followed by 3+ digits in newly registered domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1078 — Microsoft Outlook

```text
https://m-outlook.com
```

- **Domain:** `m-outlook.com`
- **Technique:** Prefix-hyphen typosquat posing as mobile Outlook sign-in
- **Detection:** Alert on single-letter-prefix brand variants: m-outlook, m-microsoft, o-office365
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1079 — Microsoft Hotmail / Live

```text
https://hotmailmc.org
```

- **Domain:** `hotmailmc.org`
- **Technique:** Typosquat domain targeting legacy Hotmail/Live account holders
- **Detection:** Flag any non-Microsoft registrable domain containing 'hotmail'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-22

### mfs-1080 — Microsoft Outlook

```text
https://outlookmc.org
```

- **Domain:** `outlookmc.org`
- **Technique:** Sibling TLD registration of the outlookmc typosquat cluster
- **Detection:** When one brand typosquat is found, sweep the same SLD across .com/.org/.net/.info
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1081 — Microsoft Outlook

```text
https://outlook-mall.com
```

- **Domain:** `outlook-mall.com`
- **Technique:** Character-swap typosquat ('mall' for 'mail') hosting Outlook sign-in clone
- **Detection:** Fuzzy-match hostnames at Levenshtein distance 1 from 'outlook-mail'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1082 — Microsoft Outlook

```text
https://outlook-email.com
```

- **Domain:** `outlook-email.com`
- **Technique:** Generic combosquat domain used as Outlook webmail credential portal
- **Detection:** Block 'outlook' + mail/email/webmail combosquats at the DNS layer
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1083 — Microsoft Outlook

```text
https://outlook-account.com
```

- **Domain:** `outlook-account.com`
- **Technique:** Account-verification themed combosquat for credential harvesting
- **Detection:** Alert on 'account'/'verify'/'secure' paired with Microsoft brand tokens in new domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1084 — Microsoft OneDrive

```text
https://onedrive-doc.com
```

- **Domain:** `onedrive-doc.com`
- **Technique:** Shared-document lure domain impersonating OneDrive file access
- **Detection:** Hunt first-time-seen domains with 'onedrive' token and short document suffixes
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1085 — Microsoft 365

```text
https://microsoftconnectportal.com
```

- **Domain:** `microsoftconnectportal.com`
- **Technique:** Fake 'Microsoft Connect' corporate portal collecting Entra ID credentials
- **Detection:** Flag 'portal'/'connect' + 'microsoft' domains not resolving to Microsoft ASNs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1086 — Microsoft

```text
https://microsoft-en.live
```

- **Domain:** `microsoft-en.live`
- **Technique:** Locale-suffix brand impersonation domain on .live TLD
- **Detection:** Alert on 'microsoft-<2-letter locale>' patterns across cheap TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1087 — Microsoft

```text
https://securite-microsoft.com
```

- **Domain:** `securite-microsoft.com`
- **Technique:** French-language security-alert combosquat for credential phishing
- **Detection:** Hunt localized security words (securite, seguridad, sicherheit) paired with 'microsoft'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1088 — Microsoft Outlook

```text
https://outlookstart.shop
```

- **Domain:** `outlookstart.shop`
- **Technique:** Brand combosquat on commerce TLD hosting Outlook sign-in clone
- **Detection:** Treat Microsoft brand tokens on .shop/.store/.sbs/.cfd as high-risk by default
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1089 — Microsoft Outlook

```text
https://outlook-serma.com
```

- **Domain:** `outlook-serma.com`
- **Technique:** Organization-targeted combosquat pairing Outlook with a victim-brand token
- **Detection:** Monitor newly registered 'outlook-<yourorg>' and '<yourorg>-outlook' permutations
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1090 — Microsoft

```text
https://microsofts.pro
```

- **Domain:** `microsofts.pro`
- **Technique:** Pluralized brand typosquat on .pro TLD
- **Detection:** Block SLD 'microsofts' on every TLD; it is never legitimate
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1091 — Microsoft 365

```text
https://microsoftonline-ms.com
```

- **Domain:** `microsoftonline-ms.com`
- **Technique:** Suffix-appended typosquat of microsoftonline.com for M365 sign-in capture
- **Detection:** Hunt 'microsoftonline-*' and '*-microsoftonline' registrable domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1092 — Microsoft / Copilot

```text
https://microsoftaideveloper.com
```

- **Domain:** `microsoftaideveloper.com`
- **Technique:** AI/Copilot-themed brand impersonation domain luring developer sign-ins
- **Detection:** Flag 'microsoft' + ai/copilot/developer token combinations in new registrations
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1093 — Microsoft 365

```text
https://microsoft364.org
```

- **Domain:** `microsoft364.org`
- **Technique:** Digit-shift typosquat of 'microsoft365' (364 for 365)
- **Detection:** Generate digit-shift variants of 365 (364/366/3665) and block proactively
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1094 — Microsoft 365

```text
https://sync-microsoft.online
```

- **Domain:** `sync-microsoft.online`
- **Technique:** Mailbox 'sync required' themed combosquat on .online TLD
- **Detection:** Alert on sync/update/migrate verbs paired with 'microsoft' in first-seen domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1095 — Microsoft Hotmail / Live

```text
https://sarahspledgerlakecamp-hotmail.com
```

- **Domain:** `sarahspledgerlakecamp-hotmail.com`
- **Technique:** Victim-organization combosquat appending '-hotmail' to a target name
- **Detection:** Monitor '<yourorg>-hotmail' / '<yourorg>-outlook' registrations via CT logs and WHOIS feeds
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1096 — Microsoft Outlook

```text
https://outlookledger.com
```

- **Domain:** `outlookledger.com`
- **Technique:** Finance-themed Outlook combosquat used for invoice/payment credential lures
- **Detection:** Hunt 'outlook' paired with finance tokens (ledger, invoice, payment, statement)
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1097 — Microsoft Outlook

```text
https://outlooklandscapes.info
```

- **Domain:** `outlooklandscapes.info`
- **Technique:** Innocuous-looking Outlook combosquat on .info TLD used as sign-in host
- **Detection:** Flag brand tokens on .info/.click/.cfd regardless of the surrounding words
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1098 — Microsoft Outlook

```text
https://outlookdemo.info
```

- **Domain:** `outlookdemo.info`
- **Technique:** 'Demo'-labelled staging domain for an Outlook credential-harvesting kit
- **Detection:** Hunt demo/test/staging + brand token domains; kit operators often leave them live
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1099 — Microsoft OneDrive

```text
https://onedrivetigerp.click
```

- **Domain:** `onedrivetigerp.click`
- **Technique:** Random-suffix OneDrive combosquat on .click TLD
- **Detection:** Block all Microsoft brand tokens on .click; near-zero legitimate use
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1100 — Microsoft OneDrive

```text
https://onedrive-docs.com
```

- **Domain:** `onedrive-docs.com`
- **Technique:** Shared-document lure combosquat for OneDrive sign-in capture
- **Detection:** Deny-list onedrive-doc/onedrive-docs/onedrivedoc permutations across TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1101 — Microsoft

```text
https://microsoftwera.com
```

- **Domain:** `microsoftwera.com`
- **Technique:** Random-token brand impersonation domain from a bulk-registration cluster
- **Detection:** Cluster new 'microsoft<random>' domains by registrar and nameserver to catch the whole batch
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1102 — Microsoft

```text
https://microsoftrecover.com
```

- **Domain:** `microsoftrecover.com`
- **Technique:** Account-recovery themed combosquat harvesting credentials and MFA codes
- **Detection:** Alert on recover/reset/unlock verbs with 'microsoft' in newly seen hostnames
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1103 — Microsoft

```text
https://microsoft-mentors.com
```

- **Domain:** `microsoft-mentors.com`
- **Technique:** Fake Microsoft programme/partner site fronting an M365 sign-in page
- **Detection:** Flag 'microsoft-<word>.com' registrations outside Microsoft's registrar accounts
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1104 — Microsoft 365 / Entra ID

```text
https://microsoft-auth.online
```

- **Domain:** `microsoft-auth.online`
- **Technique:** Explicit auth-themed combosquat impersonating Entra ID sign-in
- **Detection:** High-fidelity rule: any host matching 'microsoft.*auth' not under microsoft.com/microsoftonline.com
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1105 — Microsoft

```text
https://galilea-microsoft.com
```

- **Domain:** `galilea-microsoft.com`
- **Technique:** Target-name-prefixed combosquat impersonating a tenant-specific Microsoft portal
- **Detection:** Watch CT logs for certificates on '<customername>-microsoft.*'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1106 — Microsoft 365

```text
https://360behavioralhealth-microsoft.com
```

- **Domain:** `360behavioralhealth-microsoft.com`
- **Technique:** Healthcare-organization combosquat posing as that tenant's Microsoft login
- **Detection:** Alert on newly registered domains containing a known customer/partner name plus 'microsoft'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-19

### mfs-1107 — Microsoft OneDrive

```text
https://televisaunivision-onedrive.com
```

- **Domain:** `televisaunivision-onedrive.com`
- **Technique:** Media-company combosquat impersonating a branded OneDrive share portal
- **Detection:** Monitor '<brand>-onedrive' and '<brand>-sharepoint' registrations for your org and partners
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1108 — Microsoft Outlook

```text
https://outlooksync.cfd
```

- **Domain:** `outlooksync.cfd`
- **Technique:** Mailbox-sync lure combosquat on .cfd TLD
- **Detection:** Block Microsoft brand tokens on .cfd/.sbs/.icu/.autos outright
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1109 — Microsoft Outlook

```text
https://outex-money-outlook.sbs
```

- **Domain:** `outex-money-outlook.sbs`
- **Technique:** Finance-lure combosquat on .sbs TLD mixing a fake exchange name with Outlook
- **Detection:** Alert on multi-token hyphenated .sbs domains containing 'outlook'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1110 — Microsoft OneDrive

```text
https://onedrivevault.com
```

- **Domain:** `onedrivevault.com`
- **Technique:** Fake 'OneDrive Personal Vault' sign-in combosquat
- **Detection:** Hunt onedrive + vault/secure/locker tokens in first-seen domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1111 — Microsoft

```text
https://microsoftwarcraft.com
```

- **Domain:** `microsoftwarcraft.com`
- **Technique:** Gaming-themed brand impersonation domain fronting a Microsoft account sign-in
- **Detection:** Flag 'microsoft' + Xbox/game-title tokens; Microsoft gaming brands use xbox.com domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1112 — Microsoft Azure / Entra ID

```text
https://microsoftsovereigncloud.com
```

- **Domain:** `microsoftsovereigncloud.com`
- **Technique:** Enterprise 'Sovereign Cloud' themed impersonation domain targeting admin credentials
- **Detection:** Alert on 'microsoft' + cloud/azure/sovereign/gov tokens registered outside Microsoft
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1113 — Microsoft

```text
https://microsoftperception.com
```

- **Domain:** `microsoftperception.com`
- **Technique:** Generic brand-impersonation domain from a bulk 'microsoft<word>' registration batch
- **Detection:** Pivot on registrant email / NS records to enumerate sibling microsoft* domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1114 — Microsoft 365

```text
https://microsoftonline-live.com
```

- **Domain:** `microsoftonline-live.com`
- **Technique:** Compound typosquat merging microsoftonline and live brand strings
- **Detection:** Regex: microsoftonline[-_.a-z0-9]+ outside microsoftonline.com → block
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1115 — Microsoft 365

```text
https://microsoftnline-p.net
```

- **Domain:** `microsoftnline-p.net`
- **Technique:** Dropped-character typosquat of microsoftonline ('nline') for sign-in capture
- **Detection:** Fuzzy-match omission/insertion variants of 'microsoftonline' in DNS and proxy logs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1116 — Microsoft Bookings

```text
https://microsoftbookingz.top
```

- **Domain:** `microsoftbookingz.top`
- **Technique:** Microsoft Bookings themed combosquat (z-suffix) on .top TLD
- **Detection:** Hunt z/s-pluralized Microsoft product names (bookingz, teamz, formz) in new domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1117 — Microsoft Bookings

```text
https://microsoftbookingz.com
```

- **Domain:** `microsoftbookingz.com`
- **Technique:** Sibling .com registration of the microsoftbookingz lure cluster
- **Detection:** Sweep matching SLDs across TLDs when one member of a cluster is identified
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1118 — Microsoft 365

```text
https://microsoft365.studio
```

- **Domain:** `microsoft365.studio`
- **Technique:** Exact 'microsoft365' brand string on .studio TLD, apex of a known phishing host tree
- **Detection:** Block the whole zone, not just known subdomains, once any host under it is flagged
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1119 — Microsoft

```text
https://microsoft-support.help
```

- **Domain:** `microsoft-support.help`
- **Technique:** Fake Microsoft support portal on .help TLD (tech-support + credential phishing)
- **Detection:** Alert on 'support'/'helpdesk' + 'microsoft' domains on .help/.live/.support TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1120 — Microsoft OneDrive

```text
https://firewall-onedrive.com
```

- **Domain:** `firewall-onedrive.com`
- **Technique:** Security-themed OneDrive combosquat implying a scan/quarantine of shared files
- **Detection:** Hunt firewall/scan/quarantine/defender tokens paired with Microsoft brand names
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-18

### mfs-1121 — Microsoft Outlook

```text
https://outlookicon.com
```

- **Domain:** `outlookicon.com`
- **Technique:** Generic Outlook combosquat hosting a cloned sign-in page
- **Detection:** Baseline all 'outlook*' registrable domains; only outlook.com/office.com are legitimate
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1122 — Microsoft Outlook

```text
https://outlookbot.com
```

- **Domain:** `outlookbot.com`
- **Technique:** Automation/bot-themed Outlook combosquat for mailbox credential capture
- **Detection:** Flag 'outlook' + bot/api/sync tokens in newly registered domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1123 — Microsoft Outlook

```text
https://outlookanalysis.com
```

- **Domain:** `outlookanalysis.com`
- **Technique:** Reporting-themed Outlook combosquat used as credential landing page
- **Detection:** Correlate first-seen 'outlook*' domains with inbound mail link clicks in the same hour
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1124 — Microsoft Office 365

```text
https://office365accs.com
```

- **Domain:** `office365accs.com`
- **Technique:** Account-abbreviation combosquat ('accs') impersonating Office 365 login
- **Detection:** Hunt 'office365' + acct/accs/account tokens; also indicative of account-resale infrastructure
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1125 — Microsoft 365

```text
https://microsoftonlinesecurity.shop
```

- **Domain:** `microsoftonlinesecurity.shop`
- **Technique:** Security-alert combosquat merging microsoftonline + security on .shop TLD
- **Detection:** Block 'microsoftonline' as a substring on all non-Microsoft registrable domains
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1126 — Microsoft 365

```text
https://microsoft364.net
```

- **Domain:** `microsoft364.net`
- **Technique:** Digit-shift typosquat of microsoft365 on .net TLD
- **Detection:** Pre-emptively block microsoft364/366/3655 across common TLDs
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1127 — Microsoft Teams

```text
https://microsoft-tems.com
```

- **Domain:** `microsoft-tems.com`
- **Technique:** Dropped-character typosquat of Microsoft Teams used for meeting-join sign-in lures
- **Detection:** Fuzzy-match 'teams' omission variants (tems, teams-, taems) with 'microsoft'
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1128 — Microsoft 365

```text
https://microsoft-sap.com
```

- **Domain:** `microsoft-sap.com`
- **Technique:** Dual-brand combosquat (Microsoft + SAP) targeting enterprise SSO credentials
- **Detection:** Alert on domains combining two enterprise vendor brands; near-always phishing
- **Source:** phishunt.io — https://phishunt.io/newregistration/microsoft/
- **Status:** active
- **First seen:** 2026-11-17

### mfs-1129 — Microsoft 365

```text
https://view-stmt.uprevia.com/login?method=signin&mode=secure&client_id=8a30ed6-53592-41922-0d22-aaab5901c&privacy=on&sso_reload=true&offer_ref=https%3A%2F%2Flogin.microsoftonline.com%2F
```

- **Domain:** `view-stmt.uprevia.com`
- **Technique:** Phishing kit on a hijacked/throwaway domain; fake M365 login with offer_ref pointing at the real login.microsoftonline.com to look legitimate
- **Detection:** Hunt proxy URLs containing 'offer_ref=https%3A%2F%2Flogin.microsoftonline.com' or the query triplet method=signin&mode=secure&sso_reload=true
- **Source:** OpenPhish — https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1130 — Microsoft Outlook

```text
http://outlook-8.onrender.com
```

- **Domain:** `outlook-8.onrender.com`
- **Technique:** Credential-harvesting Outlook sign-in clone hosted on free Render.com PaaS subdomain
- **Detection:** Alert on proxy/DNS requests to *.onrender.com hosts whose page title or form posts reference Outlook/Microsoft sign-in; onrender.com is rarely a legitimate corporate auth destination
- **Source:** OpenPhish (via phishunt.io) — https://phishunt.io/source/openphish/
- **Status:** active
- **First seen:** 2026-11-25

### mfs-1131 — Microsoft Outlook / Office 365

```text
https://outlook.accountonline-officeportal.lunarvelvetshell.org
```

- **Domain:** `outlook.accountonline-officeportal.lunarvelvetshell.org`
- **Technique:** Deep-subdomain brand stuffing — 'outlook.accountonline-officeportal' prefixed onto an unrelated attacker apex to fake an Outlook account portal
- **Detection:** Hunt DNS/proxy logs for FQDNs containing 'outlook', 'officeportal' or 'accountonline' as left-hand labels where the registrable domain is NOT microsoft.com/microsoftonline.com/live.com
- **Source:** phishunt.io Microsoft brand feed — https://phishunt.io/suspicious/microsoft/
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1132 — Microsoft 365 (Entra ID device code)

```text
https://black-friday-angebote.yann-docs-0112600.workers.dev
```

- **Domain:** `black-friday-angebote.yann-docs-0112600.workers.dev`
- **Technique:** OAuth device-code phishing — fake Microsoft 'identity verification' page tells victim to generate a code and paste it into the real Microsoft sign-in, granting attacker tokens; reached via Constant Contact → S3 → Cloudflare Workers redirect chain
- **Detection:** Alert on Entra ID sign-in logs with authenticationProtocol = deviceCode where the client app is unexpected (e.g. Microsoft Authentication Broker / Visual Studio Code) and the IP ASN differs from the user's normal egress; also block *.workers.dev at the proxy
- **Source:** ThreadLinqs Intelligence (TL-2026-6716) — https://intel.threadlinqs.com/threat/TL-2026-6716
- **Status:** active
- **First seen:** 2026-11-23

### mfs-1133 — Microsoft 365 (Entra ID device code)

```text
https://sedwick-doc-file-f56764355.file-shared-document-folder.workers.dev
```

- **Domain:** `sedwick-doc-file-f56764355.file-shared-document-folder.workers.dev`
- **Technique:** EvilTokens PhaaS post-takedown host — fake shared-document lure driving OAuth device-code flow against Microsoft 365
- **Detection:** Hunt web proxy logs for requests to /api/device/start or device-login endpoints on *.workers.dev, and correlate with deviceCode sign-ins in Entra ID within the next 15 minutes
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-1134 — Microsoft 365 (Entra ID device code)

```text
https://shared-docx-onlineauth.file-docs-p8763.workers.dev
```

- **Domain:** `shared-docx-onlineauth.file-docs-p8763.workers.dev`
- **Technique:** EvilTokens PhaaS host — 'shared docx / online auth' lure fronting Microsoft device-code account takeover
- **Detection:** Block and alert on newly observed *.workers.dev subdomains containing 'docx', 'onlineauth', 'portail' or 'file-shared'; pair with Entra ID deviceCode sign-in alerting
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-1135 — Microsoft 365 (Entra ID device code)

```text
https://altitude-immobilier-portail.cloud-storage-id0346.workers.dev
```

- **Domain:** `altitude-immobilier-portail.cloud-storage-id0346.workers.dev`
- **Technique:** EvilTokens PhaaS host — organization-branded 'portail' lure leading to Microsoft device-code token theft
- **Detection:** Pivot on the shared Workers parent namespace cloud-storage-id0346/0347.workers.dev; any subdomain under it should be treated as malicious
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-04

### mfs-1136 — Microsoft 365 (Entra ID device code)

```text
https://goodstoknowfr-portal.cloud-storage-id0347.workers.dev
```

- **Domain:** `goodstoknowfr-portal.cloud-storage-id0347.workers.dev`
- **Technique:** EvilTokens PhaaS host — victim-org-branded portal page fronting Microsoft OAuth device-code flow
- **Detection:** Alert when a user visits a *.workers.dev host containing their own org name immediately before a deviceCode authentication in Entra ID
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-10-31

### mfs-1137 — Microsoft 365 (Entra ID device code)

```text
https://view-secure-document-f5rd-b-7rg0.msteinberg.workers.dev
```

- **Domain:** `view-secure-document-f5rd-b-7rg0.msteinberg.workers.dev`
- **Technique:** EvilTokens PhaaS host — 'view secure document' lure driving Microsoft device-code consent
- **Detection:** Regex proxy logs for workers.dev hostnames matching 'view-secure-document' or random 4-6 char suffix patterns; these are single-use EvilTokens lure hosts
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-02

### mfs-1138 — Microsoft 365 (Entra ID device code)

```text
https://wetransfer-access-2btsq9nkh-awareness4.vercel.app
```

- **Domain:** `wetransfer-access-2btsq9nkh-awareness4.vercel.app`
- **Technique:** EvilTokens PhaaS host on Vercel — WeTransfer file-access lure that pivots to Microsoft device-code authentication
- **Detection:** Flag *.vercel.app hostnames containing third-party brand names ('wetransfer', 'onedrive', 'sharepoint'); legitimate WeTransfer never serves from vercel.app
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-03

### mfs-1139 — Microsoft 365 (Entra ID device code)

```text
https://tokenaccess.hornedepots.com
```

- **Domain:** `tokenaccess.hornedepots.com`
- **Technique:** EvilTokens PhaaS host on attacker-registered apex — 'tokenaccess' subdomain serving the device-code lure
- **Detection:** Hunt for the literal subdomain label 'tokenaccess' in DNS/TLS SNI logs; combine with Entra ID deviceCode sign-in correlation
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-1140 — Microsoft 365 (Entra ID device code)

```text
https://signature-processing.armstrongslypka.com
```

- **Domain:** `signature-processing.armstrongslypka.com`
- **Technique:** EvilTokens PhaaS host — e-signature themed lure fronting Microsoft device-code account takeover
- **Detection:** Block the whole armstrongslypka.com apex; hunt subdomains named 'signature-processing' / 'document-management' across newly registered domains
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-1141 — Microsoft 365 (Entra ID device code)

```text
https://document-management.armstrongslypka.com
```

- **Domain:** `document-management.armstrongslypka.com`
- **Technique:** EvilTokens PhaaS host — document-management lure leading to Microsoft OAuth device-code token theft
- **Detection:** Same-apex sibling of signature-processing.armstrongslypka.com — blocklist at the registrable-domain level rather than per host
- **Source:** VMRay Labs — https://www.vmray.com/hunting-eviltokens-residual-activity-after-takedown/
- **Status:** active
- **First seen:** 2026-11-05

### mfs-1142 — Microsoft 365

```text
https://cgfcbftdsf-microsoft-auth-portal.static.hf.space
```

- **Domain:** `cgfcbftdsf-microsoft-auth-portal.static.hf.space`
- **Technique:** AI-generated fake Microsoft sign-in page built with Hugging Face DeepSite and hosted free on Hugging Face Spaces; exfiltrates credentials to a Telegram bot then redirects to real Outlook
- **Detection:** Alert on any *.hf.space request from corporate endpoints whose Space slug contains 'microsoft', 'auth', 'login' or 'portal'; outbound api.telegram.org from a browser session is a second strong signal
- **Source:** Aikido Security — https://www.aikido.dev/blog/hugging-face-phishing-pages
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1143 — Microsoft 365

```text
https://ffncthyhhdd-skema-security-portal.static.hf.space
```

- **Domain:** `ffncthyhhdd-skema-security-portal.static.hf.space`
- **Technique:** DeepSite-built Microsoft credential page on Hugging Face Spaces, branded as a target university's 'security portal'
- **Detection:** Treat *.static.hf.space as a non-business category and block by default; hunt Space slugs that combine an org name with 'security'/'portal'
- **Source:** Aikido Security — https://www.aikido.dev/blog/hugging-face-phishing-pages
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1144 — Microsoft 365

```text
https://dfgfgg-skemavision-sparkles.static.hf.space
```

- **Domain:** `dfgfgg-skemavision-sparkles.static.hf.space`
- **Technique:** DeepSite-built Microsoft sign-in clone on Hugging Face Spaces using a randomized owner handle and benign-looking Space name
- **Detection:** Randomized keyboard-mash owner handles (e.g. 'dfgfgg', 'cgfcbftdsf', 'ffncthyhhdd') on hf.space are a reliable phishing indicator — hunt the owner label, not the brand keyword
- **Source:** Aikido Security — https://www.aikido.dev/blog/hugging-face-phishing-pages
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1145 — Microsoft 365

```text
https://67gsf00.3utilities.com/
```

- **Domain:** `67gsf00.3utilities.com`
- **Technique:** Multi-hop redirect chain into reverse-proxy (AiTM) fake Microsoft sign-in; recipient address carried in URL fragment
- **Detection:** Alert on proxy/DNS hits to *.3utilities.com (dynamic-DNS) and on outbound URLs containing a '#' fragment that matches a local user's SMTP address
- **Source:** ThreadLinqs Intel (TL-2026-6951) — https://intel.threadlinqs.com/threat/TL-2026-6951
- **Status:** active
- **First seen:** 2026-11-27

### mfs-1146 — Microsoft 365

```text
https://gmxe3s.studiview.vu/bd0cb56d9086
```

- **Domain:** `gmxe3s.studiview.vu`
- **Technique:** Intermediate hop in 'Verify Access' AiTM chain; random subdomain + hex path per recipient
- **Detection:** Flag first-seen .vu TLD domains with single-label random subdomains in web proxy logs; low-reputation + no prior org history
- **Source:** ThreadLinqs Intel (TL-2026-6951) — https://intel.threadlinqs.com/threat/TL-2026-6951
- **Status:** active
- **First seen:** 2026-11-27

### mfs-1147 — Microsoft 365

```text
https://app.totalesafety.com/us/ghdjg-uuids
```

- **Domain:** `app.totalesafety.com`
- **Technique:** Fake verification screen hop preceding Microsoft credential-harvest page
- **Detection:** Hunt proxy logs for paths matching /us/*-uuids on non-corporate domains; correlate with Microsoft-themed inbound mail in the same 10-minute window
- **Source:** ThreadLinqs Intel (TL-2026-6951) — https://intel.threadlinqs.com/threat/TL-2026-6951
- **Status:** active
- **First seen:** 2026-11-27

### mfs-1148 — Microsoft 365

```text
https://armantejaratmoghadam.ir/cgi/css/
```

- **Domain:** `armantejaratmoghadam.ir`
- **Technique:** Compromised legitimate site used as redirector to Microsoft AiTM phishing page
- **Detection:** Alert on requests to /cgi/css/ style directory paths on .ir domains; treat compromised-CMS redirectors as high risk when referrer is webmail
- **Source:** ThreadLinqs Intel (TL-2026-6951) — https://intel.threadlinqs.com/threat/TL-2026-6951
- **Status:** active
- **First seen:** 2026-11-27

### mfs-1149 — Microsoft 365 / Entra ID

```text
https://damane.cloud
```

- **Domain:** `damane.cloud`
- **Technique:** NakedPages phishing framework backend reached via abuse of the real login.microsoftonline.com OAuth authorize endpoint (prompt=none redirect_uri abuse)
- **Detection:** Hunt Entra ID sign-in/audit logs for consent or authorize events on multi-tenant app IDs 6ef7853e-61e3-4265-af74-b197f5230b19 and 981f26f8-00c9-407a-9fd9-058d374656f8, then pivot on the redirect host
- **Source:** Eye Security Labs — https://labs.eye.security/microsoft-login-page-abused-as-phishing-redirector/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1150 — Microsoft 365 / Entra ID

```text
https://yukazimani.com
```

- **Domain:** `yukazimani.com`
- **Technique:** NakedPages credential-harvest page delivered via login.microsoftonline.com open-redirect-style OAuth redirect_uri abuse
- **Detection:** Block/alert on any non-Microsoft redirect_uri observed in /common/oauth2/v2.0/authorize URLs in mail bodies and proxy logs
- **Source:** Eye Security Labs — https://labs.eye.security/microsoft-login-page-abused-as-phishing-redirector/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1151 — Microsoft 365 / Entra ID

```text
https://chouests.com
```

- **Domain:** `chouests.com`
- **Technique:** NakedPages variant; Cloudflare Worker CAPTCHA gate fronting the fake Microsoft sign-in
- **Detection:** Correlate a *.workers.dev CAPTCHA hop immediately followed by a first-seen .com host and then an Entra ID sign-in from a new ASN
- **Source:** Eye Security Labs — https://labs.eye.security/microsoft-login-page-abused-as-phishing-redirector/
- **Status:** active
- **First seen:** 2026-11-20

### mfs-1152 — Microsoft Account / Azure

```text
https://azure-microsoft-account-securitusa.clicketcloud.com
```

- **Domain:** `azure-microsoft-account-securitusa.clicketcloud.com`
- **Technique:** Typosquat subdomain ('securitusa') on a shared hosting provider serving a fake Microsoft account security page
- **Detection:** Regex proxy/DNS for hostnames containing both 'microsoft' and 'securit' outside microsoft.com; alert on any 'azure-microsoft-*' label
- **Source:** PhishPin — https://www.phishpin.com/phishing/microsoft-account
- **Status:** active
- **First seen:** 2026-11-26

### mfs-1153 — Microsoft Account

```text
https://microsoftaccountverification.validations.repl.co
```

- **Domain:** `microsoftaccountverification.validations.repl.co`
- **Technique:** Free dev-platform hosting (Replit) serving a 'account verification' credential-harvest clone
- **Detection:** Block *.repl.co for corporate users or alert on any repl.co hostname containing microsoft/office/outlook labels
- **Source:** PhishPin — https://www.phishpin.com/phishing/microsoft-account
- **Status:** active
- **First seen:** 2026-11-26

### mfs-1154 — Outlook / Microsoft Account

```text
https://auth-outlook-microsoft-account-com-000000000000-redi.s3.ap-northeast-2.amazonaws.com
```

- **Domain:** `auth-outlook-microsoft-account-com-000000000000-redi.s3.ap-northeast-2.amazonaws.com`
- **Technique:** S3 static-website bucket abuse; brand keywords stuffed into the bucket name to spoof an auth redirect
- **Detection:** Hunt for S3 website endpoints whose bucket name contains 'microsoft', 'outlook', 'auth' or 'redi'; these are never legitimate Microsoft auth hosts
- **Source:** PhishPin — https://www.phishpin.com/phishing/microsoft-account
- **Status:** active
- **First seen:** 2026-11-26

### mfs-1155 — Microsoft 365

```text
https://my-documents-reviews-shared-document-review.live-document-m365.workers.dev
```

- **Domain:** `my-documents-reviews-shared-document-review.live-document-m365.workers.dev`
- **Technique:** EvilTokens OAuth device-code phishing; document-review lure page issues a real Microsoft device code to steal access/refresh tokens
- **Detection:** Hunt Entra ID sign-in logs for authenticationProtocol = deviceCode from unexpected ASNs/countries; block *.workers.dev subdomains containing 'm365' or 'document'
- **Source:** Cybersecurity News / GBHackers (EvilTokens post-takedown tracking) — https://cybersecuritynews.com/eviltokens-phishing/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-1157 — Microsoft 365 / Exchange Online

```text
https://voicemail.documentshare027545.workers.dev
```

- **Domain:** `voicemail.documentshare027545.workers.dev`
- **Technique:** EvilTokens device-code phishing using a voicemail-notification lure
- **Detection:** Same-parent pivot: any sibling subdomain of a known malicious *.workers.dev parent (documentshare027545) should be blocked wholesale
- **Source:** Cybersecurity News (EvilTokens) — https://cybersecuritynews.com/eviltokens-phishing/
- **Status:** active
- **First seen:** 2026-10-30

### mfs-1161 — Microsoft 365

```text
https://bidinvitation-portal.cloud-storage-id0348.workers.dev
```

- **Domain:** `bidinvitation-portal.cloud-storage-id0348.workers.dev`
- **Technique:** EvilTokens device-code phishing with procurement 'bid invitation' portal lure
- **Detection:** Flag cloud-storage-id0*.workers.dev parents (0346/0347/0348) as a single malicious family; alert on tender/bid-themed external portals requesting M365 login
- **Source:** Cybersecurity News (EvilTokens) — https://cybersecuritynews.com/eviltokens-phishing/
- **Status:** active
- **First seen:** 2026-11-10

### mfs-1170 — Microsoft 365 / Entra ID

```text
https://workportalsso.com
```

- **Domain:** `workportalsso.com`
- **Technique:** Fake corporate 'SSO work portal' lure in the AI-event invitation campaign; 'Continue with Microsoft' leads to Kali365 device-code or VoidProxy AiTM capture
- **Detection:** Hunt first-seen domains combining 'sso' + 'portal'/'work'; alert on Entra ID sign-ins where the app is a device-code grant from a residential ASN
- **Source:** ThreatDefence — https://threatdefence.com/article/event-invitation-phishing-detection-hunting-prevention
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1171 — Microsoft 365 / Entra ID

```text
https://ssoeventportal.com
```

- **Domain:** `ssoeventportal.com`
- **Technique:** Event-registration SSO lure funnelling victims to Microsoft sign-in proxies (VoidProxy AiTM)
- **Detection:** Block newly registered domains matching /sso.*(event|portal|meeting)/; correlate clicks with collection server 217.60.102.48
- **Source:** ThreatDefence — https://threatdefence.com/article/event-invitation-phishing-detection-hunting-prevention
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1172 — Microsoft 365 / Entra ID

```text
https://ssomeetingportal.com
```

- **Domain:** `ssomeetingportal.com`
- **Technique:** Fake meeting-SSO portal in the same event-invite cluster; harvests Microsoft work-account sessions
- **Detection:** Same regex family as ssoeventportal.com; also alert on any external 'meeting portal' host that renders a Microsoft logon form
- **Source:** ThreatDefence — https://threatdefence.com/article/event-invitation-phishing-detection-hunting-prevention
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1173 — Microsoft 365 (Anthropic/Claude-themed lure)

```text
https://claudewebinnar.com
```

- **Domain:** `claudewebinnar.com`
- **Technique:** Typosquat AI-webinar invite ('webinnar') offering free AI access; 'Sign in with Microsoft' routes to a Microsoft sign-in proxy
- **Detection:** Hunt for AI-vendor typosquats (claude/openai/anthropic + webinar/event/rsvp) in mail and proxy logs; these lures target work-account SSO, not consumer accounts
- **Source:** ThreatDefence — https://threatdefence.com/article/event-invitation-phishing-detection-hunting-prevention
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1174 — Microsoft 365 / Google Workspace

```text
https://gle-access-eventregister.icu
```

- **Domain:** `gle-access-eventregister.icu`
- **Technique:** Event-registration lure domain in the AI-events cluster presenting both Microsoft and Google sign-in options
- **Detection:** Block the .icu TLD or alert on any .icu host appearing in inbound mail; this cluster reuses .icu heavily
- **Source:** ThreatDefence — https://threatdefence.com/article/event-invitation-phishing-detection-hunting-prevention
- **Status:** active
- **First seen:** 2026-11-21

### mfs-1175 — Microsoft 365 / Entra ID

```text
https://passkeyhelpdesk.com
```

- **Domain:** `passkeyhelpdesk.com`
- **Technique:** Help-desk impersonation (voice/SMS/Teams) driving victims to a fake Microsoft passkey/MFA enrollment page; AiTM session-token theft
- **Detection:** Alert on Entra ID 'authentication method registration' events (new passkey/FIDO2) shortly after a sign-in from a new device; block passkey-themed external domains
- **Source:** CyberPress — https://cyberpress.org/passkey-phishing-hijacks-microsoft-365/
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1176 — Microsoft 365 / Entra ID

```text
https://secure-passkey.com
```

- **Domain:** `secure-passkey.com`
- **Technique:** Fake Microsoft passkey-setup portal used for AiTM credential and session capture, then Graph API abuse
- **Detection:** Hunt for Graph API enumeration (users/groups/directoryRoles) from a token whose sign-in immediately followed a new passkey registration
- **Source:** CyberPress — https://cyberpress.org/passkey-phishing-hijacks-microsoft-365/
- **Status:** active
- **First seen:** 2026-11-24

### mfs-1177 — Microsoft 365 / Entra ID

```text
https://add-passkey.com
```

- **Domain:** `add-passkey.com`
- **Technique:** Wildcard-subdomain phishing (e.g. contoso.add-passkey.com) embedding the victim's company name to spoof a Microsoft passkey enrollment flow
- **Detection:** DNS-hunt for any subdomain of add-passkey.com matching your own tenant/brand name; a company-named subdomain on a third-party root is a reliable targeting signal
- **Source:** CyberPress — https://cyberpress.org/passkey-phishing-hijacks-microsoft-365/
- **Status:** active
- **First seen:** 2026-11-24

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// Network/proxy hits to catalogued fake Microsoft sign-in hosts
let FakeMsHosts = dynamic(["creyt.cl", "sharepointonline-microsoft.com", "www.microsofl.compras-ok.com", "microsoftoutlook.flazio.online", "microsoft0117.vercel.app", "onedrive-1-one.vercel.app", "wahat-ipp.sa-onedrive.com", "validar-micuenta-outlook.yzz.me", "microsoft-online.gr", "microsoft-telemetry.at", "outlook.us.org", "miicro67soft.vercel.app", "oosoftlms.weebly.com", "knkddkmlmeaedd.weebly.com", "security-server-website--danlelbacker.replit.app", "admin-suport-update-com.weebly.com", "help.microsofth.com", "auth.microsofth.com", "apps.microsofth.com", "azure.microsofth.com", "cloud.microsofth.com", "com.microsofth.com", "data.microsofth.com", "dotnet.microsofth.com", "edge.microsofth.com", "flow.microsofth.com", "security-server-page--michaelfrank112.replit.app", "kalgaaaaa.webflow.io", "biesse.en-onedrive.com", "aiapp2.outlook1.cc", "arasyaplastic.com", "www.sharepoint-notification.vercel.app", "pay.myoffice365.ninja", "office365login-1f9d1.web.app", "office365-ff2ac.firebaseapp.com", "owa-mail-auth.firebaseapp.com", "officeadmin2026.weebly.com", "microsoftoniine.my", "outlook.accountantsclaim.com", "login-microsoftonline.pl", "www.microsoft-office365.site", "micronosoft.com", "microsoftt7.vercel.app", "teams.microsoftonline-sharepoint.online", "microsoftturkey.com", "microsoftturkiye.com", "projectshare.ngrok.pro", "www.sharepoint-eight-alpha.vercel.app", "owalotte.net", "aminsheikh72.github.io", "office365-ff2ac.web.app", "outlooksa.vercel.app", "sharepnt.ngrok.pro", "api.hotmail666.com", "usdt.hotmail666.com", "microsoft.o356.ee", "outlook-mailer.com", "login.microsoftofice.cz", "login.microsoftofice.cz", "authenticate-microsoftonline.com", "auth-microsoft.app", "microsoftoine.com", "microsoft-support-center.com", "microsoft365api.com", "microsoftup.top", "outlook-verify-session.top", "outlookmailbox.com", "microsoftsupport.digital", "care-microsoft.com", "hotmaill.live", "outlook-verif.com", "onedrivedocs.xn--q9jyb4c", "office365online.com", "outlookts.com", "saferlink-outlook.com", "microsoftoffice365.top", "onedrives-msa-document-access.online", "onedrive-sync.top", "updtes-microsoft.com", "microsofty-security.com", "defend-microsoft.com", "folder-onedrive-live.com", "accounts-outlook.com", "accountprotection-microsofts.click", "accountprotection-microsofts.website", "accountprotection-microsofts.store", "accountprotection-microsofts.sbs", "accountprotection-microsofts.monster", "accountprotection-microsofts.cyou", "accountprotection-microsofts.buzz", "notification-outlook.com", "outlook40394343.web.app", "outlook40394343.firebaseapp.com", "verificarcuenta-micros0ft2026way.zya.me", "goldcreekconcrete.com", "goldcreekconcrete.org", "openai.eventrsvp.app", "spacex.eventrsvp.app", "anthropic.rsvpconnect-events.com", "register.rsvpconnect-events.com", "62zr4vcasl.shifts.icu", "continue-to-office-.ggleventapi.icu", "login.wbdssologin.app", "wbdssologin.app", "nextconfirmationlogin.officegocrqb.com", "continueevenregistration.officegocrqb.com", "continuessoevent.officegocrqb.com", "signincomplete.offcevent-login.com", "offcevent-login.com", "office.com-access-sharepoint.com", "eventrsvp-217-60-102-48.sslip.io", "splace.co.za", "sdocshares.auth.outlook2026common.copilos26.csr-rooflng.com", "pdocshared.payments2026.outlooks.common.ecmholdlnggroup.com", "login.microsoftofice.cz", "microsoftontine.com", "microsoftonilne-na.com", "login--microsoftonline.com", "microsoft365emailessentials.online", "hotmaill.shop", "cdn-microsoft.top", "outlook-s.com", "rustic-outlook.com", "notes-to-outlook.com", "outlookmailgmail.com", "outlookcentertop.biz", "outlook366.com", "outlooktracker.com", "outlook-info.com", "review-outlook.com", "onedriverdocument.com", "onedrivedisk.com", "onedrivea.net", "microsoftsetup.com", "microsofts.network", "microsoftupdate.site", "microsoftupdate.pro", "microsoft-update.surf", "microsoft365essential.com", "microsoft365-download-office.com", "microsoft365s.com", "microsofttl.com", "office365store.com", "partner-office365.org", "tickets-microsoft.com", "hotmailsistermail.com", "auth.login.office365.cloud.onedrive.outlook.atlarchitacts.com", "authorize.copilot.outlook.common.microsoft0365.atlarchitacts.com", "copilot.login.office365outlook.cloud.onedrive.atlarchitacts.com", "reauth.copilot.common.outlook.mcloud365.atlarchitacts.com", "awemode.outlookoffice365.microsoftcopilots.docshare.linnwest.us", "copilots.outlook.cloud.microsoft.andersonelevators.com", "copilots.outlook.cloud.microsoft.syrosconstructlon.com", "statement.docdriveoauth.authorized.copilot.syrosconstructlon.com", "docshare.auth.copilot.outlook.onedrive.common.earthlink-net.com", "docshare.auth.copilot.outlook.onedrive.common.evergreenerg.com", "docshare.auth.copilot.outlook.onedrive.common0.evergreenerg.com", "docshare.auth.copilot.outlook.onedrive.common.northemheating.com", "docshare.auth.copilot.outlookonedrive.common.northemheating.com", "docshare.auth2026.onedrive.outlooksdocument.csr-rooflng.com", "docshares.auth2026.outlookcommon.copilots.commm.csr-rooflng.com", "sdocshares.auth.outlook.copilos26.general.csr-rooflng.com", "sdocshares.authoutlooks.common.copilots2026.hathormson.com", "pdocshared.documents2026.docs.shared.ecmholdlnggroup.com", "efaxdoc.auth.login.outlook.office365.tescoccontrols.com", "efaxdoc.auth.outlook2026common.copilos26.bettylnc.com", "payapp.auth.outlook2026common.copilos26.bettylnc.com", "efaxdoc.auth.outlook2026common.copilos26.ikextal-co-kr.com", "pdfdocshared.auth.outlook2026common.copilos26.ikextal-co-kr.com", "efaxdoc.auth.outlook2026common.copilos26.kone-inc.com", "efaxdoc.documents2026.cmc.docs.shared.matchlinemechanicallc.com", "efaxdoc.documents2026.docs.shared.lakeviewscustom.com", "ecosys.newdocument2026.pdfdocshared.tntileandmarbleinc.com", "login.microsoft365.outlook.copilotsoffice365.lntactpr.com", "login.office365outlooks.microsoft.cloud-outlook.naregruop.com", "naregruop.com", "m365cloud.login.outlook.office365.azgymfloor.com", "azgymfloor.com", "outlookdrive.microsoftonline.common.oauth2.client.buycerm.com", "reauth.copilot.auth.outlook.mcloud365.buycerm.com", "reauth.copilot.auth.outlook.mcloud365.myhalnc.com", "reauth.docs.copilot.auth02.outlook.mcloud365.argentventuras.com", "outlookoffice365.microsoftcopilots.vigilantlnc.com", "statement.outlookoffice365.microsoftcopilots.calmechc.net", "calmechc.net", "statements.outlook.office365microsoft.payment.run.stoneclty.com", "shared.paymentsclouds.statementsapproved.jetbusinesscapltal.com", "wsochares.authpayments.common.paid2026.bullochdirtwroks.com", "sedocs.docs.payrol2026.common.copilots2026.vatrarnsformer.com", "0ff365access.mooo.com", "bennett002.mooo.com", "0utlook0ffice365admin.twilightparadox.com", "office0365login.2waky.com", "off365mail.club", "flow55.chickenkiller.com", "swiftii.chickenkiller.com", "kilishy.qhigh.com", "linking.mefound.com", "gregor.justdied.com", "atlantictriad.ignorelist.com", "auth-loadingdocuments.online", "eccentric-authentication.com", "logins-offcevents.icu", "accounts.logins-offcevents.icu", "ydgjgdbhoa.shifts.icu", "nxinet.com", "lvborses.com", "secure-docs.liveoakfarmsllc.net", "durakdisplay.com", "securelogin.qimmxn.icu", "itencrypted.co", "householdwares.co", "liva-fit.com", "uouso.net", "wbconnecticut.net", "microsoft-winupdate.com", "entry.richmondmarketingsystems.org", "5df1ab.richmondmarketingsystems.org", "7c3206.richmondmarketingsystems.org", "fee349.richmondmarketingsystems.org", "28f4bc.richmondmarketingsystems.org", "exit.richmondmarketingsystems.org", "richmondmarketingsystems.org", "pilotjobsnetwork.com", "nscoifas.com.br", "microsoftsonline.sbs", "microsoftsonline.pro", "microsoftsonline.cfd", "m365online-microsoft.cam", "microsoft0.com", "microsoftdesktop.com", "mb-detailling84-hotmail.com", "microsoftindonesia.com", "microsoftedge.homes", "rnicrosoft-outlook.com", "microsft-outlook.com", "microsoft365-login.online", "microsoft-auth365.com", "outlookshield.com", "outlookshield.site", "outlooklab.app", "open-onedrive.online", "onedrivehelp.com", "hotmail.ceo", "xn--microsoftonine-5kc.com", "microsoft-onl1ne.com", "micros0ftauth.com", "microsoft-login.online", "office365defender.com", "microsoftsupport.fun", "your-hotmail-live.com", "storage-microsoft-ewc.shop", "shield-microsoft.com", "outlooks.page", "outlook-kwwoerden.one", "hotmaililil.shop", "brimembal.com", "viewpdfdocument2.weebly.com", "viewcompleteddocument.weebly.com", "dmpmnnu-smoky-96.vercel.app", "ucsg365.vercel.app", "www.ucsg365.vercel.app", "newlogss.github.io", "owa-mail-auth.web.app", "onedrive-4-nine.vercel.app", "site.com-microsoftonline-ondrive.ca", "index-html.info", "eventrsvp.app", "rsvpconnect-events.com", "signinwith-microsoft.sbs", "pro-hotmail.com", "outlook-mailsecure.com", "office365web.com", "office365max.com", "microsoftreset.com", "microsoftmails.com", "microsoft-oneshare.com", "microsoftatgtcdc.com", "microsoft365.art", "microsoftretailer.com", "houseprice-outlook.app", "s3-microsoft.com", "cdn-microsoft-data.com", "login-microsoft-virtual.com", "sharepoint-microsoftonline.com", "hotmail-two.vercel.app", "csmgroup.blu-foods.com", "gpimmlgration.com", "microsoftonline-sharepoint.online", "holytrip.com", "outlook-live365.github.io", "hawkinsinc.microsoft-alerts.org", "reallifeaccounting.com", "mivorantul.com", "url7489.newbooker.com", "u118254266.ct.sendgrid.net", "outagerestored.sbs", "outagefixed.sbs", "moments-notice.com", "em4493.moments-notice.com", "planetmaison.com", "em.newbooker.com", "url.newbooker.com", "u113727626.ct.sendgrid.net", "u118250677.ct.sendgrid.net", "domain.onedrive-live-shared-folder-attachment-microsoft365.com", "www.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "login-outlook365.yzz.me", "notifications.microsoft-ssl.com", "microsoftwordob.blogspot.com", "plugins.sugar-outlook.com", "microsoft365updates.com", "outlookmail.social", "office365licensingsupport.com", "microsoft365businessbasic.com", "microsoft.updata.net.cn", "onedrive.at-us.therelayservice.com", "outlook.verifytoken.com", "outlook.webaccess-alert.com", "microsoftjk.eu.org", "office365.rricrosoft-offices.org", "security.email-microsoft.com", "office365.internal-alerts.com", "reactivar-micr osoft-live.iceiy.com", "microsoft.citrix-sharing.com", "microsoft-alpha.vercel.app", "m.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "www.m.www.znzfgdld.login.microsoftonline-billing-verification-secured-help.51-254-125-38.cpanel.site", "webmail.login-microsoft-update-billing-online-secure-mainapp.20-14-89-105.cpanel.site", "cpanel.login-microsoft-update-billing-online-secure-mainapp.20-14-89-105.cpanel.site", "www.www.www.login.microsoftonline-billing-verification-secured-help.8-219-97-148.cpanel.site", "aflryvbz.microsoftonline-billing-verification-secured-help.52-234-33-034.cpanel.site", "microsoftonline-billing-verification-secured-help.52-234-33-034.cpanel.site", "rgnmsfve.mgsfpgkn.zyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "www.login.microsoftonline-billing-verification-secured-help.03-129-34-049.cpanel.site", "www.cbndbysw.login.microsoftonline-billing-verification-secured-help.03-129-34-049.cpanel.site", "www.vkpsourd.login.microsoftonline-billing-verification-secured-help.54-037-73-097.cpanel.site", "www.wthpqpte.login.microsoftonline-billing-verification-secured-help.54-037-73-097.cpanel.site", "www.gttgvoej.microsoftonline-billing-verification-secured-help.134-209-251-140.cpanel.site", "www.login.microsoftonline-billing-verification-secured-help.167-71-169-104.cpanel.site", "account.microsoft.signin.resetting.password.21512121.dogsitters.ie", "admin.foroshgahma.com", "objectstorage.us-phoenix-1.oraclecloud.com", "microwindow-e9fvg7ahe0cxf6a6.z02.azurefd.net", "xn--smarktt-y0a.net", "scontitech.emlnk9.com", "scontitech.activehosted.com", "polwanlo.vip", "merlekw.workers.dev", "maxjln.workers.dev", "c30d9e770432bc4-id-gate.bandgdruback1.workers.dev", "bandgdruback1.workers.dev", "okmjoqzhle.klavontrix.com", "klavontrix.com", "uoowsdiftk.mivorantul.com", "app.naturekojamibaramet.cyou", "naturekojamibaramet.cyou", "businessexperience.cfd", "click.newbooker.com", "em.planetmaison.com", "url2830.planetmaison.com", "login.microsoftonline.rcm-portal.at", "login.microsoftonline.bamboohr.app", "login.m-microsoft.com", "copilot.m365cloud-microsoft.com", "outlookquarantinenotice.com", "hotmail666.com", "9l2v3vupv5.synerghylnksloads.cfd", "tgg5rqrdcb.synerghylnksloads.cfd", "ngjedt0xrv.promtateusachorloadscorp.sbs", "5txpm30dqe.krointechbillpaycheckingusalexingto.sbs", "base-hub-yw7q.p-xxorevv8.workers.dev", "security-awareness.microsoft365.studio", "outlook-notifications.com", "microsofth.com", "smartscreen.microsofth.com", "rewardsplatform.microsofth.com", "random.microsofth.com", "mp.microsofth.com", "learn.microsofth.com", "hostmaster.microsofth.com", "email.microsofth.com", "packaging.onedrive.business", "login.microsoftonline.xrb.okx.mybluehost.me", "mail.login.microsoftonline.xrb.okx.mybluehost.me", "microsoftsignin.azurewebsites.net", "outlookmails.de", "mail.outlookmails.de", "outlook-silk-nine.vercel.app", "jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "test.jsqnjzyg.login.microsoftonline-billing-verification-secured-help.161-35-102-243.cpanel.site", "msteamsjoinmeetinginvite.online", "msteamsjoinmeetinginvites.online", "msteamsmeetings.online", "msteams-ai.com", "accounts.billingmicrosloft365.site", "login-msftportal.com", "download-outlook.com", "mylogin-microsoftonline.com", "onedrivesharepointopenspacepresentationdocuments832778328.autos", "onedrive-document-share.com", "microsofteamsetup.top", "microsoft365-app.com", "microsoft-365-user-auth-2-access-private-files.live", "outlooks.life", "outlookmc.com", "outlook-maill.com", "out1ook.vip", "onedrivedoc.net", "office365msangelacmcmahonsolicitormicrosoft.com", "microsoftrnail.com", "microsoftpdf.com", "microsoftonline.dog", "microsoft72000.com", "m-outlook.com", "hotmailmc.org", "outlookmc.org", "outlook-mall.com", "outlook-email.com", "outlook-account.com", "onedrive-doc.com", "microsoftconnectportal.com", "microsoft-en.live", "securite-microsoft.com", "outlookstart.shop", "outlook-serma.com", "microsofts.pro", "microsoftonline-ms.com", "microsoftaideveloper.com", "microsoft364.org", "sync-microsoft.online", "sarahspledgerlakecamp-hotmail.com", "outlookledger.com", "outlooklandscapes.info", "outlookdemo.info", "onedrivetigerp.click", "onedrive-docs.com", "microsoftwera.com", "microsoftrecover.com", "microsoft-mentors.com", "microsoft-auth.online", "galilea-microsoft.com", "360behavioralhealth-microsoft.com", "televisaunivision-onedrive.com", "outlooksync.cfd", "outex-money-outlook.sbs", "onedrivevault.com", "microsoftwarcraft.com", "microsoftsovereigncloud.com", "microsoftperception.com", "microsoftonline-live.com", "microsoftnline-p.net", "microsoftbookingz.top", "microsoftbookingz.com", "microsoft365.studio", "microsoft-support.help", "firewall-onedrive.com", "outlookicon.com", "outlookbot.com", "outlookanalysis.com", "office365accs.com", "microsoftonlinesecurity.shop", "microsoft364.net", "microsoft-tems.com", "microsoft-sap.com", "view-stmt.uprevia.com", "outlook-8.onrender.com", "outlook.accountonline-officeportal.lunarvelvetshell.org", "black-friday-angebote.yann-docs-0112600.workers.dev", "sedwick-doc-file-f56764355.file-shared-document-folder.workers.dev", "shared-docx-onlineauth.file-docs-p8763.workers.dev", "altitude-immobilier-portail.cloud-storage-id0346.workers.dev", "goodstoknowfr-portal.cloud-storage-id0347.workers.dev", "view-secure-document-f5rd-b-7rg0.msteinberg.workers.dev", "wetransfer-access-2btsq9nkh-awareness4.vercel.app", "tokenaccess.hornedepots.com", "signature-processing.armstrongslypka.com", "document-management.armstrongslypka.com", "cgfcbftdsf-microsoft-auth-portal.static.hf.space", "ffncthyhhdd-skema-security-portal.static.hf.space", "dfgfgg-skemavision-sparkles.static.hf.space", "67gsf00.3utilities.com", "gmxe3s.studiview.vu", "app.totalesafety.com", "armantejaratmoghadam.ir", "damane.cloud", "yukazimani.com", "chouests.com", "azure-microsoft-account-securitusa.clicketcloud.com", "microsoftaccountverification.validations.repl.co", "auth-outlook-microsoft-account-com-000000000000-redi.s3.ap-northeast-2.amazonaws.com", "my-documents-reviews-shared-document-review.live-document-m365.workers.dev", "voicemail.documentshare027545.workers.dev", "bidinvitation-portal.cloud-storage-id0348.workers.dev", "workportalsso.com", "ssoeventportal.com", "ssomeetingportal.com", "claudewebinnar.com", "gle-access-eventregister.icu", "passkeyhelpdesk.com", "secure-passkey.com", "add-passkey.com"]);
DeviceNetworkEvents
| where RemoteUrl has_any (FakeMsHosts) or RemoteDomain in~ (FakeMsHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP
```

> URLs rotate fast; block the hosts and hunt the technique, not just the literal URL.

