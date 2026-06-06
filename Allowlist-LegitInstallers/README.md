# Legitimate Installer Allowlist — Masquerading Hunt (T1036.005)

Known-good SHA256 baseline for popular macOS installers, captured directly from each vendor's official download URL. Powers a hunt query that catches files using a legitimate installer **filename** with a **different hash** — a hallmark of MITRE ATT&CK **T1036.005 — Match Legitimate Name or Location** (sub-technique of [Masquerading](https://attack.mitre.org/techniques/T1036/)).

## Why this matters

Recent campaigns (cybersecuritynews coverage of `weaponized-chatgpt-download-site`, `hackers-use-fake-claude-code-install-page`, `hackers-impersonate-ghidra-dnspy-spiderfoot`) distribute trojanized installers under genuine product names. Signature-based AV often misses them because the file is freshly compiled and the name itself looks normal. Hash allowlisting flips the logic: instead of asking *"is this file known-bad?"* we ask *"is this file claiming a known-good name yet unknown to the vendor's official hash?"*

## Contents

| File | Purpose |
|------|---------|
| `legit-installers.csv` | Hash baseline. Columns: `app, platform, arch, filename, executable_name, size_bytes, sha256, sha1, source_url, captured_at`. `filename` is the installer (e.g. `googlechrome.dmg`); `executable_name` is the binary inside `.app/Contents/MacOS/` that actually runs after install (e.g. `Google Chrome`). Watch both — the installer hash detects malicious downloads, the executable name detects malicious binaries already on disk. |
| `legit-installer-mismatch.kql` | Microsoft Defender for Endpoint / Sentinel hunt query — emits hits when a watched filename appears with a non-matching SHA256 |

## Coverage

9 macOS installers in this baseline (Claude Desktop pending — vendor endpoint blocks non-browser clients):

| App | Platform | Arch |
|-----|----------|------|
| Google Chrome | macOS | universal |
| ChatGPT Desktop | macOS | universal |
| Cursor | macOS | arm64 |
| Visual Studio Code | macOS | arm64 |
| Notion | macOS | universal |
| Slack | macOS | arm64 |
| Zoom | macOS | arm64 |
| AnyDesk | macOS | universal |
| Ghidra | cross-platform | jar |

## How to refresh

Hashes drift with every vendor release. To regenerate:

```bash
# Run from a clean working directory
mkdir -p /tmp/legit-installers && cd /tmp/legit-installers

# Download each in parallel (URLs in legit-installers.csv → source_url column)
curl -fLo googlechrome.dmg              "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg" &
curl -fLo ChatGPT.dmg                   "https://persistent.oaistatic.com/sidekick/public/ChatGPT.dmg" &
# … etc for all 9 …
wait

# Compute SHA256 + SHA1 + size and rebuild the CSV
for f in *; do
    printf '%s,%d,%s,%s\n' "$f" "$(stat -f %z "$f")" \
        "$(shasum -a 256 "$f" | awk '{print $1}')" \
        "$(shasum -a 1   "$f" | awk '{print $1}')"
done
```

## Limitations

- **Filename-only watch surface**: an attacker who renames their malicious payload to something not on the watchlist (e.g. `Setup.dmg`, `chrome_installer.dmg` instead of the exact `googlechrome.dmg`) evades this hunt. Pair with file-signing checks where possible.
- **Hash drift**: each vendor release invalidates the corresponding row. Plan to regenerate at least monthly, ideally on a schedule.
- **Universal vs arm64 distinction**: a legitimate `Cursor-darwin-x64.dmg` would fire as a mismatch against the arm64 entry. Extend the table per architecture if you support mixed fleets.
- **Cross-platform tools**: Ghidra ships as a single platform-agnostic ZIP; on Windows the same hash applies, on Linux the user might extract it differently.
- **Code-signing is the better long-term answer**: SHA256 says "bit-for-bit identical to what we captured"; signature verification says "signed by the publisher's key" and survives version updates. This allowlist is a complement, not a replacement.

## License

MIT-style — same as the parent repository. Hashes themselves are facts and not subject to copyright.
