# TIFeeds Enrichment

Threat-intel feed enrichment data — sources, classifications, and visual evidence
augmenting the raw IOC feeds in `Daily-IOCReportsCollection/`.

## phishunt_enriched.csv

Per-URL enrichment of [phishunt.io](https://phishunt.io/feed.csv) phishing feed.

**Columns**

1-16. Original phishunt feed columns:
   `url, domain, company, date, first_seen, uuid, ip, country, asn, org, cert,
   malicious_google, malicious_openphish, malicious_phishtank, malicious_tweetfeed, malicious_urlscan`
17. `sector` — derived from `company` field (banking, crypto, social, tech,
    shipping, streaming, gaming, e-commerce, payments, cloud_storage, telecom,
    government, unknown). `NA` if the page is offline.
18. `language` — ISO 639-1 primary subtag (en, es, de, fr, ru, zh, ja…) read
    from the rendered page's `<html lang="...">` attribute (with a fallback
    to `<meta http-equiv="content-language">`). `unknown` if neither is
    present, `NA` if offline.
19. `url_status` — `online` or `offline`.
20. `screenshot_path` — path (relative to this folder) of the above-the-fold
    screenshot captured at fetch time. `NA` if offline.

## screenshots/

PNG screenshots (1280×720, above-the-fold, no scroll) of online URLs at the
moment they were enriched. Filenames are the `uuid` from the original feed.

## Notes

- Visiting phishing URLs is done via headless Playwright with a fresh isolated
  context per URL, downloads aborted, no form interaction, 10s timeout.
- Offline URLs are intentionally not retried — the feed already includes
  multiple records per kit, so a single capture per UUID is sufficient.
- Updated: 2026-05-24
