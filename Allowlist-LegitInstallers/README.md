# Legitimate Installer Allowlist — Masquerading Hunt (T1036.005)

Known-good SHA256 baseline for popular macOS installers, captured directly from each vendor's official download URL. Powers a hunt query that catches files using a legitimate installer **filename** with a **different hash** — a hallmark of MITRE ATT&CK **T1036.005 — Match Legitimate Name or Location** (sub-technique of [Masquerading](https://attack.mitre.org/techniques/T1036/)).

## Why this matters

Recent campaigns (cybersecuritynews coverage of `weaponized-chatgpt-download-site`, `hackers-use-fake-claude-code-install-page`, `hackers-impersonate-ghidra-dnspy-spiderfoot`) distribute trojanized installers under genuine product names. Signature-based AV often misses them because the file is freshly compiled and the name itself looks normal. Hash allowlisting flips the logic: instead of asking *"is this file known-bad?"* we ask *"is this file claiming a known-good name yet unknown to the vendor's official hash?"*

## Contents

| File | Purpose |
|------|---------|
| `legit-installers.csv` | **Hash baseline.** Columns: `app, platform, arch, filename, executable_name, size_bytes, sha256, sha1, source_url, captured_at`. `filename` is the installer (e.g. `googlechrome.dmg`); `executable_name` is the binary inside `.app/Contents/MacOS/` that actually runs after install (e.g. `Google Chrome`). Watch both — the installer hash detects malicious downloads, the executable name detects malicious binaries already on disk. Up to **3 recent versions per product** are retained (Windows seeded from winget manifests; macOS accumulated over daily runs). |
| `legit-download-sources.csv` | **Legitimate download-URL allowlist.** Columns: `app, platform, arch, filename, source_url, match_type, notes`. The canonical official download URLs (e.g. `https://download.anydesk.com/AnyDesk.exe`). Use it to allowlist by **download origin** in network/proxy telemetry — this survives hash drift, so a genuine new release from the official URL is not flagged even when its SHA256 changes. `match_type` is `exact` (full URL), `prefix` (version varies after this path) or `domain` (host-only allowlist). |
| `legit-installer-mismatch.kql` | Microsoft Defender for Endpoint / Sentinel hunt query — emits hits when a watched filename appears with a non-matching SHA256 |

## Coverage

14 products across macOS + Windows, each with up to 3 recent versions (Windows via winget manifests, macOS accumulated over time):

| App | macOS | Windows |
|-----|-------|---------|
| Google Chrome | universal `.dmg` | x64 `.exe` (consumer) + x64 `.msi` (enterprise) |
| Microsoft Teams | universal `.pkg` | x64 `.msix` |
| Adobe Acrobat Reader | x64 `.dmg` (URL allowlist) | x64 `.exe` |
| ChatGPT Desktop | universal `.dmg` | — (Microsoft Store only — no direct URL) |
| Claude Desktop | — (Cloudflare blocks curl) | — (Cloudflare blocks curl) |
| Cursor | arm64 `.dmg` | x64 `.exe` |
| Visual Studio Code | arm64 `.zip` | x64 `.exe` |
| Notion | universal `.dmg` | x64 `.exe` |
| Slack | arm64 `.dmg` | x64 `.exe` |
| Zoom | arm64 `.pkg` | x64 `.msi` |
| AnyDesk | universal `.dmg` | x64 `.exe` |
| Mozilla Firefox | universal `.dmg` | x64 `.exe` |
| Spotify | universal `.dmg` | x64 `.exe` |
| WhatsApp | universal `.dmg` | — (Microsoft Store only — URL allowlist) |
| Ghidra | cross-platform `.zip` (one file covers Mac+Win+Linux) | (same row) |

Known gaps to revisit:
- **Claude Desktop** (both platforms): the vendor endpoint at `https://claude.ai/api/desktop/...` returns 403 to non-browser clients (Cloudflare anti-bot). Requires headless browser automation to capture.
- **ChatGPT Desktop Windows**: distributed exclusively via Microsoft Store as an `.appx`/`.msix` — no direct download URL exists.
- **WhatsApp Windows**: same situation — Microsoft Store MSIX only, so it is covered in `legit-download-sources.csv` (Store URL) but has no direct installer to hash. Its macOS build **is** hashed.

## How it refreshes

Hashes drift with every vendor release, so this baseline is regenerated **daily** and pushed automatically:

- **Windows** — the 3 latest versions per product are read from the [winget-pkgs](https://github.com/microsoft/winget-pkgs) manifests (`InstallerUrl` + `InstallerSha256`, published and validated by Microsoft). No download needed.
- **macOS** — each installer is fetched from its official URL and hashed locally; a download is skipped when the file size is unchanged, and up to 3 distinct versions accumulate over time.
- The run keeps the newest 3 distinct SHA256 per `app+platform+arch`, then commits + pushes the updated CSVs.

The refresher (`refresh.ts`, run with `bun`) is scheduled once a day. To run it on demand:

```bash
bun run refresh.ts            # refresh + commit + push
DRY=1 bun run refresh.ts      # refresh only, no git
```

## Limitations

- **Filename-only watch surface**: an attacker who renames their malicious payload to something not on the watchlist (e.g. `Setup.dmg`, `chrome_installer.dmg` instead of the exact `googlechrome.dmg`) evades this hunt. Pair with file-signing checks where possible.
- **Hash drift**: each vendor release invalidates the corresponding row. Plan to regenerate at least monthly, ideally on a schedule.
- **Universal vs arm64 distinction**: a legitimate `Cursor-darwin-x64.dmg` would fire as a mismatch against the arm64 entry. Extend the table per architecture if you support mixed fleets.
- **Cross-platform tools**: Ghidra ships as a single platform-agnostic ZIP; on Windows the same hash applies, on Linux the user might extract it differently.
- **Code-signing is the better long-term answer**: SHA256 says "bit-for-bit identical to what we captured"; signature verification says "signed by the publisher's key" and survives version updates. This allowlist is a complement, not a replacement.

## License

MIT-style — same as the parent repository. Hashes themselves are facts and not subject to copyright.
