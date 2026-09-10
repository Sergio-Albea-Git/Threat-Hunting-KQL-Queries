# Microsoft Fake Sign-In Sites Catalog

> ⚠️ **Defensive use only.** Every URL below is a **DEFANGED** malicious/illustrative
> sample kept for **detection engineering, blocklisting and threat hunting**. URLs are
> neutralised (`hxxp`, `[.]`). **Do not visit them or submit credentials.** Generic
> sample hosts (`<attacker>`, `<random>`) are placeholders — the tracker replaces them
> with real observed indicators.

This catalog documents **URLs and techniques used to impersonate Microsoft sign-in
pages** — Microsoft 365, Office, Outlook, Azure AD / **Entra ID** and Live. Attackers
clone the login flow (or reverse-proxy the real one) to steal usernames, passwords and,
increasingly, **MFA session cookies**. The goal here is to help defenders **block, hunt
and detect** Microsoft credential-phishing infrastructure — not just by the literal URL
(which rotates fast) but by the **technique and detection logic** behind each entry.

## What this repo does

- **Catalogs** each fake-sign-in pattern as a structured entry (`id`, `url`, `domain`,
  `brand`, `technique`, `detection`, `source`, `first_seen`, `last_seen`, `status`).
- **Feeds blocklists** — hosts/URLs can be exported to proxy, DNS and mail-gateway blocks.
- **Drives threat hunting** — every entry ships a **Detection** line (what to hunt for in
  proxy, mail and Entra ID sign-in logs), so it works even after the URL goes down.
- **Grows over time** — designed to be updated (manually or by an automated tracker),
  mirroring the [ClickFix Command Catalog](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/tree/main/ClickFix-Commands)
  format so both feeds stay consistent.

- **Entries:** 8 (technique patterns — seed set)
- **Last updated:** 2026-09-10
- **Maintained by:** PAI · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/tree/main/Microsoft_Fake_Sites)

## Data

- [`microsoft-fake-sites.json`](microsoft-fake-sites.json) — the structured feed (`meta` + `entries`).

### Entry schema

| Field | Description |
|-------|-------------|
| `id` | Stable identifier (`mfs-NNNN`). |
| `url` | Defanged fake sign-in URL / pattern. |
| `domain` | Hostname (or pattern) serving the fake page. |
| `brand` | Impersonated Microsoft brand. |
| `technique` | How the impersonation works (AiTM, typosquat, open redirect, quishing…). |
| `detection` | What to hunt for in logs to catch it. |
| `source` / `source_url` | Public reporting the pattern is based on (defanged). |
| `first_seen` / `last_seen` | Observation dates (`YYYY-MM-DD`). |
| `status` | `pattern`, `active`, `down`, or `unknown`. |

## Sites

| ID | Brand | Technique |
| --- | --- | --- |
| mfs-0001 | Microsoft 365 / Entra ID | AiTM reverse-proxy phishing (Evilginx / Tycoon 2FA / EvilProxy) — steals the MFA session cookie |
| mfs-0002 | Office 365 | Fake login kit dropped on a compromised WordPress / CMS |
| mfs-0003 | Microsoft 365 | Email-prefill (`#victim@corp.com`) with auto-filled username and tenant branding |
| mfs-0004 | Outlook / Microsoft 365 | Open-redirect / trusted-service abuse to hide the real landing host |
| mfs-0005 | Microsoft / Entra ID | Look-alike / typosquat domain hosting a static login clone |
| mfs-0006 | Microsoft 365 | CAPTCHA-gated phishing (Turnstile / hCaptcha) to evade sandboxes |
| mfs-0007 | Microsoft 365 / MFA | Quishing (QR-code) to a fake MFA / sign-in page on mobile |
| mfs-0008 | Outlook / Microsoft 365 | HTML-attachment / blob-URL fake login rendered locally |

---

### mfs-0001 — Microsoft 365 / Entra ID

```text
hxxps://login-microsoftonline[.]<random>[.]workers[.]dev/common/oauth2/authorize
```

- **Technique:** AiTM reverse-proxy phishing (Evilginx / Tycoon 2FA / EvilProxy) — the fake page proxies the real login.microsoftonline.com in real time to steal the session cookie and defeat MFA.
- **Detection:** Sign-ins where the client/redirect host is NOT login.microsoftonline.com but the auth flow completes; new session from an unusual ASN immediately after a phishing click; Entra ID risky sign-in + token replay from a different IP within minutes.
- **Source:** Microsoft Threat Intelligence — AiTM / Tycoon 2FA reporting — hxxps://www.microsoft[.]com/security/blog/
- **Notes:** Cloudflare Workers (`.workers.dev`) and `pages.dev` commonly abused as disposable hosting.
- **First seen:** 2026-09-10

### mfs-0002 — Office 365

```text
hxxps://<compromised-wordpress>[.]com/wp-content/office365/login[.]php
```

- **Technique:** Fake Microsoft login kit dropped on a compromised legitimate CMS (WordPress) under /wp-content or /wp-includes; credentials POSTed to an attacker collector or Telegram bot.
- **Detection:** Outbound POST to /wp-content|/wp-includes paths containing office365/login/verify; referer chain from webmail; hunt proxy logs for `*/wp-content/*login*.php`.
- **Source:** Cisco Talos / general phishing-kit reporting — hxxps://blog.talosintelligence[.]com/
- **Notes:** Legit domain reputation helps the URL bypass mail filters.
- **First seen:** 2026-09-10

### mfs-0003 — Microsoft 365

```text
hxxps://<brand>[.]<free-host>/#victim@corp[.]com
```

- **Technique:** Email-prefill phishing — the victim address is placed after `#` so the fake page auto-fills the username and renders the corporate tenant branding, increasing credibility.
- **Detection:** URL fragment (`#`) containing a full email address; page that mirrors tenant branding on a non-Microsoft host; hunt for URLs with `#` + email pattern in web logs.
- **Source:** Proofpoint / Sekoia phishing-kit analysis — hxxps://www.sekoia[.]io/en/blog/
- **Notes:** Common in Mamba 2FA / Greatness / Caffeine PhaaS kits.
- **First seen:** 2026-09-10

### mfs-0004 — Outlook / Microsoft 365

```text
hxxps://<attacker>[.]com/office/verify?redir=login[.]microsoftonline[.]com
```

- **Technique:** Open-redirect / trusted-service abuse — the visible part of the URL references a legitimate Microsoft/third-party domain while the actual landing host is attacker-controlled.
- **Detection:** URLs where a Microsoft-looking token appears in the query/path but the registrable domain is untrusted; open-redirect parameters (`redir=`, `url=`, `next=`) pointing off-domain.
- **Source:** Microsoft / general open-redirect abuse reporting — hxxps://www.microsoft[.]com/security/blog/
- **Notes:** Also abuses Google/LinkedIn/Baidu open redirects as the first hop.
- **First seen:** 2026-09-10

### mfs-0005 — Microsoft / Entra ID

```text
hxxps://microsofft-online-login[.]com/
```

- **Technique:** Look-alike / typosquat domain (extra letter, hyphenation, TLD swap such as .com/.co/.online) hosting a static clone of the Microsoft sign-in page.
- **Detection:** Newly-registered domains with edit-distance 1-2 to microsoftonline.com / office.com / login.live.com; homoglyph checks; Levenshtein/keyword hunting on NRD feeds.
- **Source:** Typosquat / brand-abuse monitoring — hxxps://www.microsoft[.]com/security/blog/
- **Notes:** Watch keywords: microsoft, msonline, office365, login, sso, mfa, secure, verify.
- **First seen:** 2026-09-10

### mfs-0006 — Microsoft 365

```text
hxxps://<attacker>[.]com/verify?cf-turnstile-response=1#login-microsoft
```

- **Technique:** CAPTCHA-gated phishing — a Cloudflare Turnstile / hCaptcha / fake human-check is placed in front of the fake MS login to block crawlers and automated sandboxes before serving the credential form.
- **Detection:** Phishing hosts that serve a challenge page to scanners but the real login form to browsers; hunt for turnstile/hcaptcha assets on non-Microsoft hosts that redirect to Microsoft-branded forms.
- **Source:** Sekoia / general PhaaS reporting — hxxps://www.sekoia[.]io/en/blog/
- **Notes:** Evasion layer; combine with AiTM (mfs-0001).
- **First seen:** 2026-09-10

### mfs-0007 — Microsoft 365 / MFA

```text
hxxps://<attacker>[.]com/o365?d=<base64-qr-target>
```

- **Technique:** Quishing (QR-code phishing) — a PDF/image email embeds a QR code pointing to a fake Microsoft MFA/sign-in page, moving the click to a mobile device outside corporate controls.
- **Detection:** Inbound mail with QR images and little text; endpoint/MDM telemetry showing mobile navigation to a Microsoft-branded non-Microsoft host shortly after mail delivery.
- **Source:** Microsoft / Barracuda quishing reporting — hxxps://www.microsoft[.]com/security/blog/
- **Notes:** Often 'review the encrypted/secure document' or 'MFA re-enrollment' lures.
- **First seen:** 2026-09-10

### mfs-0008 — Outlook / Microsoft 365

```text
hxxps://<attacker>[.]pages[.]dev/   (loads a local data:/blob: fake login)
```

- **Technique:** HTML-attachment / blob-URL phishing — an .htm attachment or a page builds the fake Microsoft login entirely from an encoded (base64/blob:) blob rendered locally, so the credential form never appears as a fetched remote page.
- **Detection:** Mail attachments (.htm/.html/.svg) that decode base64 into a login form; browser navigations to `blob:`/`data:` URIs presenting Microsoft branding; POST of credentials to a remote collector from a locally-rendered page.
- **Source:** Microsoft / Trustwave HTML-smuggling & phishing reporting — hxxps://www.microsoft[.]com/security/blog/
- **Notes:** Cloudflare Pages (`.pages.dev`), Netlify, Firebase and IPFS gateways abused as hosting.
- **First seen:** 2026-09-10

---

## Contributing

Add entries to `microsoft-fake-sites.json`, keep `id`s sequential (`mfs-NNNN`), **defang
every URL** (`hxxp`, `[.]`), and mirror the new entry into the tables/sections above. Only
submit indicators you are confident impersonate Microsoft sign-in.

## Disclaimer

Provided as-is, for defensive and educational purposes only. The maintainers are not
responsible for misuse.
