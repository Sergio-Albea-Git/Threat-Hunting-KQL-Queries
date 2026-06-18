#!/usr/bin/env bun
/**
 * IOC Reporter — Daily FileHash IOC scraper for cybersecuritynews.com
 *
 * Scrapes the homepage for article links, fetches each article,
 * extracts MD5/SHA1/SHA256/SHA512 file hashes, builds a PDF report,
 * and emails it via Gmail SMTP.
 *
 * Config: ~/.config/PAI/ioc-reporter.env
 *   GMAIL_USER=albea.notifications@gmail.com
 *   GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx   (Google App Password, not your login password)
 *   TO_EMAIL=sergio.albea@switch.ch          (optional, defaults below)
 */

import { existsSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import nodemailer from "nodemailer";
import { chromium, type Browser, type BrowserContext } from "playwright";

// ─── Config ──────────────────────────────────────────────────────────────────

const ENV_FILE = join(homedir(), ".config", "PAI", "ioc-reporter.env");
const BASE_URL = "https://cybersecuritynews.com";
const DEFAULT_TO    = "sergio.albea@switch.ch";
const DEFAULT_FROM  = "albea.notifications@gmail.com";
const CONCURRENCY = 4; // parallel article fetches within Playwright context

function loadEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  if (existsSync(ENV_FILE)) {
    const lines = readFileSync(ENV_FILE, "utf8").split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const idx = trimmed.indexOf("=");
      if (idx === -1) continue;
      env[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
    }
  }
  // Also pull from process.env (so GitLab CI/CD Variables work)
  for (const key of ["GMAIL_USER", "GMAIL_APP_PASSWORD", "TO_EMAIL"]) {
    if (process.env[key]) env[key] = process.env[key]!;
  }
  return env;
}

// ─── Types ───────────────────────────────────────────────────────────────────

export type IOCType = "MD5" | "SHA1" | "SHA256" | "SHA512" | "Domain" | "URL" | "IP" | "RegistryKey" | "Filename";

export interface IOC {
  hash: string; // kept as field name for backward compat; holds the indicator value for all types
  type: IOCType;
  articleTitle: string;
  articleUrl: string;
  confidence?: "high" | "medium";
}

export interface ArticleResult {
  url: string;
  title: string;
  iocs: IOC[];
  publishedAt?: string | null; // ISO 8601 UTC, set by csv-pusher consumers; harmless for PDF flow
  scrapedAt?: string;          // ISO 8601 UTC, when the article was first scraped (per-article first_seen)
  error?: string;
}

// ─── Scraping (Playwright — bypasses Cloudflare) ─────────────────────────────

let _browser: Browser | null = null;
let _ctx: BrowserContext | null = null;

// Retry chromium.launch up to 3 times with backoff. Defends against transient
// failures: stale browser cache, headless launch races, momentary memory
// pressure. Default Playwright launch timeout in 1.59.x is 180s — we cut it
// to 60s so a stuck launch fails fast and frees the retry budget.
async function launchWithRetry(): Promise<Browser> {
  const MAX_ATTEMPTS = 3;
  const BACKOFFS_MS = [5_000, 15_000]; // wait after attempt 1, then after attempt 2
  let lastErr: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    console.log(`[launch] attempt ${attempt}/${MAX_ATTEMPTS}`);
    // Test hook: force a launch failure to exercise the retry + failure-email path.
    if (process.env.IOC_TEST_FAIL_LAUNCH === "1") {
      throw new Error("IOC_TEST_FAIL_LAUNCH=1 — synthetic launch failure for testing");
    }
    try {
      return await chromium.launch({ headless: true, timeout: 60_000 });
    } catch (err) {
      lastErr = err;
      console.error(`[launch] attempt ${attempt} failed: ${(err as Error).message}`);
      if (attempt < MAX_ATTEMPTS) {
        const waitMs = BACKOFFS_MS[attempt - 1];
        console.log(`[launch] backing off ${waitMs}ms before retry`);
        await new Promise(r => setTimeout(r, waitMs));
      }
    }
  }
  throw lastErr;
}

async function getBrowserContext(): Promise<BrowserContext> {
  if (_ctx) return _ctx;
  _browser = await launchWithRetry();
  _ctx = await _browser.newContext({
    userAgent:
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    extraHTTPHeaders: { "Accept-Language": "en-US,en;q=0.9" },
  });
  return _ctx;
}

export async function closeBrowser() {
  await _ctx?.close();
  await _browser?.close();
  _ctx = null;
  _browser = null;
}

export async function fetchPage(url: string): Promise<string | null> {
  const ctx = await getBrowserContext();
  const page = await ctx.newPage();
  try {
    const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25_000 });
    if (!response) { console.error(`[fetchPage] no response for ${url}`); return null; }
    if (response.status() >= 400) { console.error(`[fetchPage] HTTP ${response.status()} for ${url}`); return null; }
    return await page.content();
  } catch (err) {
    console.error(`[fetchPage] error for ${url}: ${(err as Error).message}`);
    return null;
  } finally {
    await page.close().catch(() => {});
  }
}

export function extractArticleUrls(html: string): string[] {
  const urls = new Set<string>();
  const hrefRe = /href="(https?:\/\/cybersecuritynews\.com\/[^"#?]+?)"/gi;
  let m: RegExpExecArray | null;
  while ((m = hrefRe.exec(html)) !== null) {
    const url = m[1];
    // Exclude non-article paths
    if (/\/(category|tag|author|page|feed|wp-|cdn-cgi|xmlrpc|sitemap)/.test(url)) continue;
    // Exclude files with extensions (.php, .xml, .jpg, .png, etc.)
    if (/\.[a-z]{2,5}$/.test(new URL(url).pathname)) continue;
    const path = new URL(url).pathname;
    const segments = path.split("/").filter(Boolean);
    // Article slugs: exactly 1 segment, only word-chars and dashes, min 5 chars
    if (segments.length === 1 && /^[a-z0-9][a-z0-9-]{4,}$/.test(segments[0])) {
      urls.add(url.replace(/\/$/, ""));
    }
  }
  return Array.from(urls);
}

function extractTitle(html: string): string {
  const m = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (!m) return "Unknown Article";
  return m[1].replace(/\s*[–|-]\s*Cybersecurity News.*$/i, "").trim();
}

// ─── Hash Extraction ─────────────────────────────────────────────────────────

// Word-boundary isolated hex strings of exact lengths.
// Negative lookbehind/lookahead prevents matching substrings of longer hex runs.
const HASH_PATTERNS: Array<{ type: IOC["type"]; re: RegExp }> = [
  // SHA512 first so 128-char strings aren't also matched as SHA256 etc.
  { type: "SHA512", re: /(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])/g },
  { type: "SHA256", re: /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g },
  { type: "SHA1",   re: /(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])/g },
  { type: "MD5",    re: /(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])/g },
];

function extractHashes(text: string, title: string, url: string): IOC[] {
  const seen = new Set<string>();
  const iocs: IOC[] = [];

  // Strip CSS/HTML artifacts: remove style blocks, script blocks, URLs
  const clean = text
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/https?:\/\/[^\s"'<>]+/g, " ")       // remove URLs (contain hex path segments)
    .replace(/#[0-9a-fA-F]{3,8}\b/g, " ")          // remove CSS color codes
    .replace(/<[^>]+>/g, " ");                       // strip remaining tags

  for (const { type, re } of HASH_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(clean)) !== null) {
      const hash = m[0].toLowerCase();
      if (seen.has(hash)) continue;
      seen.add(hash);
      iocs.push({ hash, type, articleTitle: title, articleUrl: url });
    }
  }
  return iocs;
}

// ─── Domain / URL / IP Extraction (high-precision) ───────────────────────────
//
// Strategy: only emit IOCs with explicit malicious-context signal.
//   1. DEFANGED forms (e.g. evil[.]com, hxxp://bad.tld, 1[.]2[.]3[.]4) → high confidence,
//      auto-extract. Defanging is never used for legitimate references.
//   2. Plain forms → only extracted from inside an "Indicators of Compromise" / "IOCs"
//      / "C2" / "Malicious Domains" section heading. Outside such sections, plain
//      domains/URLs/IPs are assumed legitimate and dropped.
//
// All candidates pass through filters: allowlist of known-legit domains, RFC1918
// + reserved IP ranges, octet >255 (catches version-like strings), and a
// version-word lookbehind (catches "Chrome 124.0.0.0", "v1.2.3.4").

const DOMAIN_ALLOWLIST = new Set<string>([
  "cybersecuritynews.com",         // source itself
  "google.com", "googleapis.com", "gmail.com", "youtube.com",
  "microsoft.com", "windows.com", "office.com", "live.com", "outlook.com",
  "office365.com", "sharepoint.com", "onedrive.com", "msn.com",
  "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "git.io",
  "twitter.com", "x.com", "facebook.com", "linkedin.com", "instagram.com",
  "wikipedia.org", "mozilla.org", "apple.com", "icloud.com", "amazon.com", "aws.amazon.com",
  "cloudflare.com", "akamai.com", "fastly.com", "cloudfront.net",
  "virustotal.com", "abuse.ch", "mitre.org", "nist.gov", "cisa.gov", "us-cert.gov",
  "crowdstrike.com", "mandiant.com", "paloaltonetworks.com", "fortinet.com",
  "trendmicro.com", "kaspersky.com", "symantec.com", "mcafee.com", "sophos.com",
  "checkpoint.com", "bitdefender.com", "eset.com", "f-secure.com", "avast.com",
  "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com",
  "schema.org", "w3.org", "ietf.org",
  // Major search/forums
  "bing.com", "duckduckgo.com", "yahoo.com", "reddit.com",
  "stackoverflow.com", "stackexchange.com", "quora.com",
  // Package registries / runtimes / dev infra
  "npmjs.com", "npmjs.org", "pypi.org", "rubygems.org", "packagist.org", "nuget.org",
  "docker.com", "hub.docker.com", "ghcr.io", "quay.io",
  "jsdelivr.net", "unpkg.com",
  "python.org", "nodejs.org", "rust-lang.org", "go.dev", "golang.org", "ruby-lang.org",
  "php.net", "kernel.org", "gnu.org",
  // Distros
  "ubuntu.com", "canonical.com", "debian.org", "redhat.com", "centos.org",
  "fedoraproject.org", "archlinux.org", "alpinelinux.org",
  // Major vendors / cloud
  "adobe.com", "oracle.com", "java.com", "openjdk.org", "jetbrains.com",
  "atlassian.com", "salesforce.com", "ibm.com", "sap.com",
  "intel.com", "amd.com", "nvidia.com",
  "vmware.com", "citrix.com",
  "android.com", "googleblog.com", "blogspot.com",
]);

// Basenames of legitimate Windows/Unix tools that should NOT be flagged as
// filename IOCs even when mentioned inside an "Indicators of Compromise"
// section. These are LOLbins / system binaries / common applications —
// universally present, not actionable as standalone indicators. The article
// title still preserves context (e.g. "Hackers Use cmd.exe to Launch X").
//
// Comparison is on the lowercased BASENAME only — so `C:\Windows\System32\cmd.exe`
// is filtered too, but `%appdata%\Foo\openvr_api.dll` (suspicious path,
// non-listed basename) is preserved.
const BENIGN_FILENAME_BASENAMES = new Set<string>([
  // Windows shells / scripting hosts
  "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
  // Windows core OS binaries
  "explorer.exe", "svchost.exe", "csrss.exe", "smss.exe", "lsass.exe",
  "winlogon.exe", "services.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe",
  "conhost.exe", "dllhost.exe", "dwm.exe", "wininit.exe", "fontdrvhost.exe",
  "runtimebroker.exe", "wlanext.exe", "wuauclt.exe", "searchhost.exe", "searchindexer.exe",
  // Windows utility / LOLbin family
  "rundll32.exe", "regsvr32.exe", "regedit.exe", "msiexec.exe", "msdt.exe",
  "msbuild.exe", "msconfig.exe", "control.exe", "taskmgr.exe", "tasklist.exe", "taskkill.exe",
  "wmic.exe", "wmiprvse.exe",
  "certutil.exe", "bitsadmin.exe", "schtasks.exe", "at.exe", "sc.exe", "net.exe",
  "netstat.exe", "ipconfig.exe", "ping.exe", "tracert.exe", "arp.exe", "route.exe",
  "nslookup.exe", "hostname.exe", "systeminfo.exe", "whoami.exe", "set.exe",
  "xcopy.exe", "copy.exe", "robocopy.exe", "attrib.exe", "del.exe", "ren.exe",
  "find.exe", "findstr.exe", "where.exe", "sort.exe", "more.exe",
  "reg.exe", "runas.exe", "ftp.exe", "telnet.exe", "tftp.exe",
  "forfiles.exe", "ie4uinit.exe", "fodhelper.exe", "sdiagnhost.exe",
  // Windows user-facing
  "notepad.exe", "mspaint.exe", "calc.exe", "wordpad.exe", "snippingtool.exe",
  // Microsoft Office
  "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
  "msaccess.exe", "mspub.exe", "visio.exe", "lync.exe", "teams.exe", "ms-teams.exe",
  // Browsers
  "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe",
  "brave.exe", "vivaldi.exe", "safari.exe",
  // Comms / consumer apps
  "slack.exe", "discord.exe", "zoom.exe", "skype.exe", "whatsapp.exe", "telegram.exe",
  "spotify.exe", "steam.exe", "vlc.exe", "obs64.exe", "obs32.exe",
  // Dev tools — runtimes
  "java.exe", "javaw.exe", "javac.exe", "javaws.exe", "jar.exe",
  "python.exe", "python3.exe", "pythonw.exe", "pip.exe",
  "node.exe", "npm.exe", "npx.exe", "yarn.exe", "bun.exe", "deno.exe",
  "ruby.exe", "irb.exe", "gem.exe", "perl.exe", "perl5.exe",
  "php.exe", "composer.exe",
  // Dev tools — VCS / IDE / build
  "git.exe", "git-bash.exe", "git-cmd.exe", "tortoiseproc.exe",
  "code.exe", "code-insiders.exe", "devenv.exe", "dotnet.exe",
  "idea64.exe", "pycharm64.exe", "phpstorm64.exe", "webstorm64.exe", "rider64.exe",
  // Compression
  "7z.exe", "7zg.exe", "winrar.exe", "rar.exe", "unrar.exe", "winzip.exe",
  // Adobe (universally legit)
  "acrobat.exe", "acrord32.exe", "photoshop.exe", "illustrator.exe", "premiere.exe",
  // Remote tools (some are LOLbins; include anyway)
  "putty.exe", "winscp.exe", "filezilla.exe",

  // Unix/Linux/macOS shells
  "bash", "sh", "zsh", "ksh", "csh", "tcsh", "dash", "fish",
  // Unix coreutils
  "ls", "cat", "echo", "grep", "sed", "awk", "find", "head", "tail",
  "cp", "mv", "rm", "ln", "mkdir", "rmdir", "touch", "chmod", "chown", "stat",
  "ps", "top", "kill", "pkill", "killall", "nice", "renice",
  "df", "du", "free", "uptime", "uname", "hostname", "whoami", "id", "groups",
  "env", "export", "alias", "history",
  // Unix network
  "ssh", "scp", "rsync", "sftp", "curl", "wget", "telnet", "ftp",
  "nslookup", "dig", "host", "ping", "ip", "ifconfig", "route", "netstat", "ss",
  "tcpdump", "nc", "ncat", "socat",
  // Package managers
  "apt", "apt-get", "yum", "dnf", "pacman", "zypper", "brew", "snap", "flatpak",
  // Service / cron / privesc helpers
  "systemctl", "service", "journalctl", "crontab", "sudo", "su", "doas",
]);

/** Returns true if the given filename/path's basename is a known legitimate
 *  system binary or common application — i.e. should not be reported as an IOC. */
export function isBenignFilename(value: string): boolean {
  const basename = value.replace(/\\/g, "/").split("/").pop()?.toLowerCase() ?? "";
  return BENIGN_FILENAME_BASENAMES.has(basename);
}

/** Exported for csv-pusher post-build defense-in-depth filtering. */
export function isAllowlistedDomainExported(host: string): boolean {
  return isAllowlistedDomain(host);
}

const VERSION_WORDS = /(?:version|ver|v|build|patch|update|sdk|api|chrome|firefox|edge|safari|windows|android|ios|kernel|release|rev)$/i;

// Curated list of common TLDs (gTLDs + ccTLDs + commonly-abused free TLDs).
// Domain candidates whose final label is NOT in this set are rejected as
// non-domain (e.g., Android package names ending in .apk, file names ending
// in .zip/.gz/.tar, truncated strings ending in arbitrary words).
const COMMON_TLDS = new Set<string>([
  // gTLDs
  "com","net","org","info","biz","name","mobi","asia","tel","pro","int",
  "gov","edu","mil","aero","museum","jobs","cat","coop",
  // new gTLDs (common, including abuse-prone)
  "app","dev","io","ai","cloud","online","site","store","tech","top","xyz",
  "shop","design","network","finance","bank","link","click","party","host",
  "website","space","fun","win","racing","science","review","study","support",
  "services","club","live","today","world","life","news","blog","work",
  "agency","group","email","global","systems","solutions","digital","media",
  "pizza","wtf","tools","center","press","cyou",
  // ccTLDs (common business + commonly abused for malware)
  "us","uk","de","fr","es","it","nl","ru","cn","jp","kr","in","br","mx",
  "au","ca","ch","se","no","fi","dk","pl","be","at","cz","gr","pt","ie",
  "hk","tw","sg","my","th","ph","id","tr","ua","ar","cl","co","pe","za",
  "ae","sa","il","eg","nz","vn","nz","ro","hu","sk","si","hr","bg","lt",
  "lv","ee","is","lu","mt","cy",
  // small ccTLDs commonly used commercially or abused
  "io","co","me","tv","cc","fm","am","ws","sh","st","gs","re","ms","ly",
  "tk","ml","ga","cf","gq", // free TLDs popular with attackers
  // more new gTLDs
  "academy","accountant","actor","app","art","auction","bar","beer",
  "best","bid","bike","bingo","cafe","camera","camp","care","careers",
  "casa","cash","casino","catering","chat","cheap","christmas","church",
  "city","claims","cleaning","clinic","clothing","codes","coffee","college",
  "community","company","computer","construction","consulting","contact",
  "contractors","cool","country","coupons","credit","cricket","cruises",
  "dance","date","dating","deals","delivery","democrat","dental","dentist",
  "diamonds","diet","direct","directory","discount","doctor","dog","domains",
  "education","energy","engineer","engineering","enterprises","equipment",
  "events","exchange","expert","exposed","express","fail","family","fan",
  "fans","farm","fashion","financial","fish","fit","fitness","flights",
  "florist","flowers","football","forsale","foundation","fund","furniture",
  "gallery","games","garden","gift","gifts","gives","glass","gold","golf",
  "graphics","gratis","gripe","guide","guitars","guru","health","help",
  "hockey","holiday","home","horse","hospital","hosting","house","how",
  "immo","immobilien","industries","institute","insurance","international",
  "investments","irish","jewelry","kaufen","kim","kitchen","land","lawyer",
  "lease","legal","lgbt","life","lighting","limited","limo","loan","loans",
  "lol","love","ltd","luxury","management","market","marketing","markets",
  "mba","memorial","menu","money","mortgage","movie","navy","ninja","one",
  "page","partners","parts","pet","photo","photography","photos","pics",
  "pictures","plus","poker","porn","press","productions","properties",
  "property","pub","racing","realty","recipes","red","rehab","rent",
  "rentals","repair","report","republican","restaurant","rich","rip",
  "rocks","run","sale","salon","sarl","school","schule","science","sex",
  "sexy","singles","ski","skin","soccer","social","software","studio",
  "style","sucks","supplies","supply","surf","surgery","systems","tattoo",
  "tax","taxi","team","theater","tienda","tips","tires","tours","town",
  "toys","trade","training","travel","university","vacations","vegas",
  "ventures","vet","video","villas","vin","vip","vodka","vote","voto",
  "voyage","watch","webcam","wedding","wiki","win","wine","yoga","zone",
]);

// File extensions that look like TLDs but indicate the candidate is a file
// name, archive, or app package — never a domain.
const FILE_EXT_DENY = new Set<string>([
  "apk","xapk","ipa","exe","dll","msi","msix","msixbundle","appx",
  "pkg","dmg","iso","img","deb","rpm","snap","flatpak",
  "zip","rar","7z","tar","gz","tgz","bz2","xz","lz","lzma",
  "png","jpg","jpeg","gif","bmp","svg","webp","ico","tif","tiff",
  "pdf","doc","docx","xls","xlsx","ppt","pptx","txt","rtf","csv",
  "mp3","mp4","wav","avi","mov","mkv","webm","flv","m4a","ogg",
  "log","tmp","bak","old","sav","conf","cfg","ini",
]);

function isPrivateOrReservedIP(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true; // also rejects bad octets
  const [a, b, , d] = parts;
  if (a === 0) return true;                            // 0.0.0.0/8
  if (a === 10) return true;                           // 10.0.0.0/8
  if (a === 127) return true;                          // loopback
  if (a === 169 && b === 254) return true;             // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
  if (a === 192 && b === 168) return true;             // 192.168.0.0/16
  if (a === 224) return true;                          // multicast
  if (a >= 240) return true;                           // reserved/future
  if (a === 255) return true;                          // broadcast
  if (d === 0 || d === 255) return true;               // network base / broadcast — not host IOCs
  return false;
}

// Cloudflare's published IPv4 edge ranges (https://www.cloudflare.com/ips-v4).
// IPs in these ranges are CDN / reverse-proxy edge addresses fronting sites,
// not attacker infrastructure — capturing them yields false-positive IOCs.
// The list is stable (Cloudflare changes it rarely); refresh from the URL above
// if they announce new ranges.
const CLOUDFLARE_IPV4_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
];

function ipv4ToUint(ip: string): number | null {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

const CLOUDFLARE_RANGES = CLOUDFLARE_IPV4_CIDRS.map(cidr => {
  const [net, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (ipv4ToUint(net)! & mask) >>> 0, mask };
});

/** True if `ip` (optionally `ip:port`) falls in a Cloudflare edge range.
 *  Exported for csv-pusher post-build defense-in-depth filtering. */
export function isCloudflareIP(ip: string): boolean {
  const u = ipv4ToUint(ip.split(":")[0]);
  if (u === null) return false;
  return CLOUDFLARE_RANGES.some(r => ((u & r.mask) >>> 0) === r.base);
}

function isPlausibleDomain(host: string): boolean {
  const h = host.toLowerCase();
  const labels = h.split(".");
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  if (FILE_EXT_DENY.has(tld)) return false;            // .apk, .zip, .tar, etc.
  if (!COMMON_TLDS.has(tld)) return false;             // unknown TLD → reject
  if (/^\d+$/.test(tld)) return false;                 // numeric TLD impossible
  return true;
}

function isTemplateURL(url: string): boolean {
  // Reject URLs containing placeholder syntax that escaped HTML stripping
  // (e.g., https://<phish_site>/..., https://&lt;phish_site&gt;/...).
  return /[<>{}]|&lt;|&gt;|\$\{|%[A-Z_]+%/.test(url);
}

function refangText(t: string): string {
  // Decode common defang notations into their canonical form so downstream
  // matching/output uses normal `.` and `http(s)://`. Operates on a copy.
  return t
    .replace(/h[xX]{2}p(s?):\/\//g, "http$1://")
    .replace(/\[\s*\.\s*\]/g, ".")
    .replace(/\(\s*\.\s*\)/g, ".")
    .replace(/\[\s*dot\s*\]/gi, ".")
    .replace(/\{\s*\.\s*\}/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[\s*@\s*\]/g, "@")
    .replace(/\[\s*at\s*\]/gi, "@");
}

function isDefanged(snippet: string): boolean {
  return /\[\.\]|\(\.\)|\[dot\]|h[xX]{2}p|\{\.\}|\[:\]/.test(snippet);
}

// Locate IOC-section blocks: from a heading match to ~2000 chars after, or until
// the next clear heading-like break. Used to gate plain (non-defanged) extraction.
const IOC_SECTION_HEADINGS = /\b(indicators?\s+of\s+compromise|ioc[s]?|c2\s+(?:server|infrastructure|domain)s?|c&c\s+server|malicious\s+(?:domain|url|ip|host)s?|threat\s+indicator)\b/gi;

function findIOCSections(plain: string): string[] {
  const blocks: string[] = [];
  let m: RegExpExecArray | null;
  IOC_SECTION_HEADINGS.lastIndex = 0;
  while ((m = IOC_SECTION_HEADINGS.exec(plain)) !== null) {
    const start = m.index;
    const end = Math.min(plain.length, start + 2000);
    blocks.push(plain.slice(start, end));
  }
  return blocks;
}

const DOMAIN_RE = /(?<![\w.-])([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+\.(?:[a-z]{2,24}))(?![\w.-])/gi;
const URL_RE    = /\bhttps?:\/\/[^\s"'<>\)\]]+/gi;
const IP_RE     = /(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])/g;

// Windows Registry key paths. Matches full hive names (HKEY_LOCAL_MACHINE)
// or 4-letter short forms (HKLM/HKCU/HKCR/HKU/HKCC), followed by a backslash
// (or double-backslash from code blocks) and a path with at least 2 more segments.
// Path chars: word chars, dot, hyphen, plus, parens, braces — covers GUIDs,
// versioned paths, ProgID-style names. NO space — stops cleanly at whitespace.
const REG_KEY_RE = /\b(HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))(\\{1,2}[A-Za-z0-9_.\-+(){}\\]+){2,}/g;

// Trim trailing punctuation that often clings to the end of a registry path
// in prose (sentence punctuation, closing brackets/quotes, stray backslash).
const REG_TRIM_TRAILING = /[.,;:)\]>"'\\]+$/;

// Filename / file path IOCs. Captures bare filenames AND full paths (Windows,
// Unix, env-var) by being permissive on the prefix then validating the file
// extension against an allowlist. The regex matches a contiguous sequence of
// path-safe chars ending in `.<ext>` where ext is 1-12 alnum chars; the
// extension allowlist is checked at extraction time, not by the regex.
//
// The (?<![A-Za-z0-9:\/]) lookbehind prevents the regex from starting mid-word
// OR right after `:`/`/` — without this guard `https://evil.com/foo.exe` would
// match either at `s://` (Windows drive-letter pattern collision) or at any of
// the path slashes inside the URL.
const FILE_PATH_RE = /(?<![A-Za-z0-9:\/])(?:[A-Za-z]:[\\\/]|\\\\[A-Za-z0-9_$.\-]+[\\\/]|%[A-Z_][A-Z_0-9]*%[\\\/]|~\/|\.{1,2}[\\\/])?[A-Za-z0-9_\-.\\\/]+\.([A-Za-z0-9]{1,12})\b/g;
const FILE_TRIM_TRAILING = /[.,;:)\]>"'\\\/]+$/;

// Extensions worth surfacing as filename IOCs. Focuses on executables,
// scripts, archives, office docs, and packaging formats — the things that
// typically show up in threat intel IOC sections. Plain text/data formats
// (.json .xml .txt .md .csv .yaml) are deliberately excluded — too common.
//
// NOTE: extensions that double as common TLDs (com/app/sh/pl/py/run/one) are
// either omitted (`com`) or only accepted when accompanied by a path prefix —
// see the COMMON_TLDS check at extraction time. Bare `evil.com` is a domain,
// not a file.
const FILE_EXT_ALLOW = new Set<string>([
  // Executables / scripts (Windows). .com (DOS exec) intentionally removed:
  // overlaps with the .com TLD and is essentially extinct in modern malware.
  "exe","dll","sys","ocx","drv","cpl","scr","pif","msi","msix","msixbundle",
  "appx","appxbundle","reg","inf","chm","hta","lnk",
  // Executables / scripts (Unix/macOS)
  "elf","bin","app","pkg","dmg","deb","rpm","snap","flatpak","run",
  "so","dylib","ko","service",
  // Mobile
  "apk","xapk","ipa",
  // Scripting / batch
  "bat","cmd","ps1","psm1","ps1xml","vbs","vbe","js","jse","wsf","wsh","wsc","sct",
  "sh","bash","zsh","py","pyc","pyw","pl","rb","jar","class","groovy",
  // Archives (often droppers)
  "zip","7z","rar","tar","gz","tgz","bz2","xz","cab","arj","ace","iso","img",
  // Office (macro-bearing)
  "doc","docx","docm","dot","dotm","xls","xlsx","xlsm","xlsb","xlam","xltm",
  "ppt","pptx","pptm","potm","ppsm","rtf","odt","one","onepkg","xll",
  // Acrobat
  "pdf",
  // Misc IOC-frequent
  "application","gadget","workflow","action",
]);

function isAllowlistedDomain(host: string): boolean {
  const h = host.toLowerCase();
  if (DOMAIN_ALLOWLIST.has(h)) return true;
  // also drop subdomains of allowlisted apex domains
  for (const apex of DOMAIN_ALLOWLIST) {
    if (h.endsWith("." + apex)) return true;
  }
  return false;
}

function precededByVersionWord(text: string, idx: number): boolean {
  // Look back up to 12 chars for a version-context word.
  const start = Math.max(0, idx - 16);
  const before = text.slice(start, idx);
  // Strip a trailing space and check the last word.
  const lastWord = before.match(/([A-Za-z]+)\s*$/);
  if (!lastWord) return false;
  return VERSION_WORDS.test(lastWord[1]);
}

function extractDomainsURLsIPs(html: string, title: string, articleUrl: string): IOC[] {
  // Strip script/style/tags then refang.
  const stripped = html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ");
  const refanged = refangText(stripped);

  const sections = findIOCSections(refanged);
  const plainScopes = sections; // plain (non-defanged) extraction is gated to these

  const sourceHost = (() => { try { return new URL(articleUrl).hostname.toLowerCase(); } catch { return ""; } })();

  const seen = new Set<string>();
  const out: IOC[] = [];
  const push = (value: string, type: IOCType, confidence: "high" | "medium") => {
    const v = value.toLowerCase().replace(/[.,;:)\]]+$/, "");
    const key = `${type}:${v}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ hash: v, type, articleTitle: title, articleUrl, confidence });
  };

  // 1. DEFANGED extraction across the whole article — high confidence.
  //    We re-scan the original (still defanged) stripped text, then refang each match.
  for (const m of stripped.matchAll(/h[xX]{2}ps?:\/\/\S+/g)) {
    const refangedMatch = refangText(m[0]);
    if (isTemplateURL(refangedMatch)) continue;
    push(refangedMatch, "URL", "high");
  }
  // Defanged domains/IPs: detect by presence of [.] or [dot] then refang
  for (const m of stripped.matchAll(/[A-Za-z0-9-]+(?:\s*(?:\[\.\]|\[dot\]|\(\.\))\s*[A-Za-z0-9-]+)+/gi)) {
    const refangedMatch = refangText(m[0]).toLowerCase();
    if (IP_RE.test(refangedMatch)) {
      IP_RE.lastIndex = 0;
      const ipMatch = refangedMatch.match(/^(\d{1,3}\.){3}\d{1,3}$/);
      if (ipMatch && !isPrivateOrReservedIP(refangedMatch) && !isCloudflareIP(refangedMatch)) {
        push(refangedMatch, "IP", "high");
      }
    } else if (DOMAIN_RE.test(refangedMatch)) {
      DOMAIN_RE.lastIndex = 0;
      if (!isAllowlistedDomain(refangedMatch) && refangedMatch !== sourceHost && isPlausibleDomain(refangedMatch)) {
        push(refangedMatch, "Domain", "high");
      }
    }
    DOMAIN_RE.lastIndex = 0;
    IP_RE.lastIndex = 0;
  }

  // 2. PLAIN extraction — only inside IOC sections, medium confidence.
  for (const block of plainScopes) {
    // URLs
    URL_RE.lastIndex = 0;
    let mu: RegExpExecArray | null;
    while ((mu = URL_RE.exec(block)) !== null) {
      const u = mu[0];
      if (isTemplateURL(u)) continue;
      let host = "";
      try { host = new URL(u).hostname.toLowerCase(); } catch { continue; }
      if (!host || host === sourceHost || isAllowlistedDomain(host)) continue;
      if (!isPlausibleDomain(host)) continue;
      push(u, "URL", "medium");
    }
    // Domains (bare, no scheme)
    DOMAIN_RE.lastIndex = 0;
    let md: RegExpExecArray | null;
    while ((md = DOMAIN_RE.exec(block)) !== null) {
      const d = md[1].toLowerCase();
      if (d === sourceHost || isAllowlistedDomain(d)) continue;
      if (!isPlausibleDomain(d)) continue;
      // skip if it's actually part of a URL we already captured
      if (block.slice(Math.max(0, md.index - 8), md.index).match(/https?:\/\/[^\s]*$/)) continue;
      push(d, "Domain", "medium");
    }
    // IPs
    IP_RE.lastIndex = 0;
    let mi: RegExpExecArray | null;
    while ((mi = IP_RE.exec(block)) !== null) {
      const ip = mi[1];
      if (isPrivateOrReservedIP(ip) || isCloudflareIP(ip)) continue;
      if (precededByVersionWord(block, mi.index)) continue;
      push(ip, "IP", "medium");
    }
    // Registry keys
    REG_KEY_RE.lastIndex = 0;
    let mr: RegExpExecArray | null;
    while ((mr = REG_KEY_RE.exec(block)) !== null) {
      let raw = mr[0];
      // Normalize escaped backslashes from code-block source: \\ → \
      const normalized = raw.replace(/\\\\/g, "\\").replace(REG_TRIM_TRAILING, "");
      // Require at least 2 path segments beyond the hive
      const segments = normalized.split("\\").filter(Boolean);
      if (segments.length < 3) continue; // hive + 2+
      push(normalized, "RegistryKey", "medium");
    }
    // Filenames / file paths (executables, scripts, archives, office docs)
    FILE_PATH_RE.lastIndex = 0;
    let mf: RegExpExecArray | null;
    while ((mf = FILE_PATH_RE.exec(block)) !== null) {
      const raw = mf[0];
      let ext = mf[1].toLowerCase();
      // Normalize versioned Unix shared libs: `libfoo.so.1`/`libfoo.dylib.2`
      // would otherwise capture the version number as the extension.
      if (/^\d+$/.test(ext)) {
        const m = raw.match(/\.(so|dylib)\.\d+$/i);
        if (m) ext = m[1].toLowerCase();
      }
      if (!FILE_EXT_ALLOW.has(ext)) continue;
      // Skip if this candidate sits inside a URL we already captured. Window of
      // 256 chars lets us detect even fairly long URLs ending right before our
      // match position (no whitespace between the URL start and us).
      const before = block.slice(Math.max(0, mf.index - 256), mf.index);
      if (/https?:\/\/[^\s]*$/.test(before)) continue;
      // Skip bare candidates whose extension is a common TLD — those are domains
      // (`evil.com`, `bad.app`, `c2.sh`) leaking past DOMAIN_RE's 3-label minimum.
      // We still accept them when accompanied by a path separator or env-var
      // prefix, because `/tmp/script.sh` and `%APPDATA%\foo.app` ARE filenames.
      const hasPathPrefix = /[\\\/]|%[A-Z_]/.test(raw);
      if (!hasPathPrefix && COMMON_TLDS.has(ext)) continue;
      // Normalize double backslashes from code-block source, trim trailing junk
      let normalized = raw.replace(/\\\\/g, "\\").replace(FILE_TRIM_TRAILING, "");
      // Skip if it doesn't actually contain the extension (trim went too far)
      if (!new RegExp(`\\.${ext}$`, "i").test(normalized)) continue;
      // Min length 5 (e.g. "a.exe" too generic)
      if (normalized.length < 5) continue;
      // Skip LOLbins / common legitimate apps (basename-only check)
      if (isBenignFilename(normalized)) continue;
      push(normalized, "Filename", "medium");
    }
  }

  return out;
}

export function extractPublishedAt(html: string): string | null {
  // 1) Open Graph: <meta property="article:published_time" content="2026-05-11T07:00:00+00:00">
  let m = html.match(/<meta\s+property=["']article:published_time["']\s+content=["']([^"']+)["']/i)
       || html.match(/<meta\s+content=["']([^"']+)["']\s+property=["']article:published_time["']/i);
  if (m) { const iso = toIsoUtc(m[1]); if (iso) return iso; }

  // 2) JSON-LD: "datePublished": "..."
  for (const block of html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    const body = block[1];
    const dm = body.match(/"datePublished"\s*:\s*"([^"]+)"/);
    if (dm) { const iso = toIsoUtc(dm[1]); if (iso) return iso; }
  }

  // 3) <time datetime="..."> (first occurrence, typically the article timestamp)
  m = html.match(/<time[^>]*datetime=["']([^"']+)["']/i);
  if (m) { const iso = toIsoUtc(m[1]); if (iso) return iso; }

  return null;
}

function toIsoUtc(raw: string): string | null {
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  return d.toISOString();
}

export async function scrapeArticle(url: string): Promise<ArticleResult> {
  const html = await fetchPage(url);
  if (!html) return { url, title: "Fetch failed", iocs: [], error: "HTTP error or timeout" };
  const title = extractTitle(html);
  const hashIocs = extractHashes(html, title, url);
  const otherIocs = extractDomainsURLsIPs(html, title, url);
  const publishedAt = extractPublishedAt(html);
  return { url, title, iocs: [...hashIocs, ...otherIocs], publishedAt };
}

// ─── Parallel fetch with concurrency cap ─────────────────────────────────────

export async function scrapeAll(urls: string[]): Promise<ArticleResult[]> {
  const results: ArticleResult[] = [];
  for (let i = 0; i < urls.length; i += CONCURRENCY) {
    const batch = urls.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(scrapeArticle));
    results.push(...batchResults);
  }
  return results;
}

// ─── PDF Generation ──────────────────────────────────────────────────────────

const COLORS = {
  headerBg:   rgb(0.10, 0.14, 0.22),
  headerText: rgb(1, 1, 1),
  sectionBg:  rgb(0.94, 0.96, 1.0),
  accent:     rgb(0.20, 0.40, 0.80),
  tableHeader:rgb(0.15, 0.25, 0.50),
  tableRow1:  rgb(0.97, 0.97, 0.97),
  tableRow2:  rgb(1, 1, 1),
  text:       rgb(0.10, 0.10, 0.10),
  muted:      rgb(0.45, 0.45, 0.45),
  red:        rgb(0.75, 0.15, 0.15),
  green:      rgb(0.10, 0.55, 0.25),
};

async function buildPDF(results: ArticleResult[], runDate: Date): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const fontRegular = await doc.embedFont(StandardFonts.Helvetica);
  const fontBold    = await doc.embedFont(StandardFonts.HelveticaBold);
  const fontMono    = await doc.embedFont(StandardFonts.Courier);

  const PAGE_W = 595.28; // A4
  const PAGE_H = 841.89;
  const MARGIN  = 40;
  const COL_W   = PAGE_W - MARGIN * 2;

  let page = doc.addPage([PAGE_W, PAGE_H]);
  let y = PAGE_H - MARGIN;

  function newPage() {
    page = doc.addPage([PAGE_W, PAGE_H]);
    y = PAGE_H - MARGIN;
  }

  function ensureSpace(needed: number) {
    if (y - needed < MARGIN + 20) newPage();
  }

  function drawRect(x: number, py: number, w: number, h: number, color: ReturnType<typeof rgb>) {
    page.drawRectangle({ x, y: py, width: w, height: h, color });
  }

  function text(
    str: string,
    x: number,
    py: number,
    opts: { size?: number; font?: typeof fontRegular; color?: ReturnType<typeof rgb>; maxWidth?: number } = {}
  ) {
    const { size = 10, font = fontRegular, color = COLORS.text, maxWidth } = opts;
    // Truncate if too long
    let s = str;
    if (maxWidth && font.widthOfTextAtSize(s, size) > maxWidth) {
      while (s.length > 4 && font.widthOfTextAtSize(s + "…", size) > maxWidth) {
        s = s.slice(0, -1);
      }
      s += "…";
    }
    page.drawText(s, { x, y: py, size, font, color });
  }

  // ── Header banner ──
  const headerH = 70;
  drawRect(0, PAGE_H - headerH, PAGE_W, headerH, COLORS.headerBg);
  text("IOC Report", MARGIN, PAGE_H - 30, { size: 22, font: fontBold, color: COLORS.headerText });
  const dateStr = runDate.toUTCString().replace(" GMT", " UTC");
  text(`cybersecuritynews.com  ·  ${dateStr}`, MARGIN, PAGE_H - 52, { size: 10, color: rgb(0.7, 0.8, 1.0) });
  y = PAGE_H - headerH - 16;

  // ── Collect all IOCs ──
  const allIocs: IOC[] = [];
  const seenGlobal = new Set<string>();
  for (const r of results) {
    for (const ioc of r.iocs) {
      if (!seenGlobal.has(ioc.hash)) {
        seenGlobal.add(ioc.hash);
        allIocs.push(ioc);
      }
    }
  }

  const byType: Record<string, IOC[]> = {
    MD5: [], SHA1: [], SHA256: [], SHA512: [],
    Domain: [], URL: [], IP: [], RegistryKey: [], Filename: [],
  };
  for (const ioc of allIocs) byType[ioc.type].push(ioc);

  const articlesWithIOCs = results.filter(r => r.iocs.length > 0).length;
  const articlesScanned  = results.filter(r => !r.error).length;
  const failed           = results.filter(r => r.error).length;

  // ── Summary box ──
  ensureSpace(80);
  drawRect(MARGIN, y - 70, COL_W, 70, COLORS.sectionBg);
  page.drawRectangle({ x: MARGIN, y: y - 70, width: 4, height: 70, color: COLORS.accent });
  text("SUMMARY", MARGIN + 12, y - 16, { size: 11, font: fontBold, color: COLORS.accent });
  const summaryItems = [
    `Articles scanned: ${articlesScanned}`,
    `Articles with IOCs: ${articlesWithIOCs}`,
    `Total unique IOCs: ${allIocs.length}`,
    failed > 0 ? `Failed fetches: ${failed}` : null,
    `MD5: ${byType.MD5.length}  ·  SHA1: ${byType.SHA1.length}  ·  SHA256: ${byType.SHA256.length}  ·  SHA512: ${byType.SHA512.length}`,
    `Domains: ${byType.Domain.length}  ·  URLs: ${byType.URL.length}  ·  IPs: ${byType.IP.length}  ·  Registry Keys: ${byType.RegistryKey.length}  ·  Filenames: ${byType.Filename.length}`,
  ].filter(Boolean) as string[];
  let sy = y - 32;
  for (const item of summaryItems) {
    text(item, MARGIN + 12, sy, { size: 9.5, color: COLORS.text });
    sy -= 14;
  }
  y -= 84;

  if (allIocs.length === 0) {
    ensureSpace(40);
    text("No IOCs detected in today's articles.", MARGIN, y, { size: 11, color: COLORS.muted });
    y -= 20;
  }

  // ── Per-type tables ──
  const SECTION_ORDER = ["SHA256", "SHA512", "SHA1", "MD5", "Domain", "URL", "IP", "RegistryKey", "Filename"] as const;
  for (const sectionType of SECTION_ORDER) {
    const iocs = byType[sectionType];
    if (iocs.length === 0) continue;

    ensureSpace(48);
    // Section heading
    drawRect(MARGIN, y - 22, COL_W, 22, COLORS.tableHeader);
    const heading = sectionType === "Domain"      ? "DOMAINS"
                  : sectionType === "URL"         ? "URLS"
                  : sectionType === "IP"          ? "IPS"
                  : sectionType === "RegistryKey" ? "REGISTRY KEYS"
                  : sectionType === "Filename"    ? "FILENAMES / PATHS"
                  : sectionType;
    text(`${heading}  (${iocs.length})`, MARGIN + 8, y - 15, { size: 11, font: fontBold, color: COLORS.headerText });
    y -= 22;

    // Column widths: indicator | source article
    const valueColW = sectionType === "MD5"         ? 180
                    : sectionType === "SHA1"        ? 220
                    : sectionType === "SHA256"      ? 290
                    : sectionType === "SHA512"      ? COL_W - 140
                    : sectionType === "IP"          ? 120
                    : sectionType === "Domain"      ? 240
                    : sectionType === "RegistryKey" ? COL_W - 160
                    : sectionType === "Filename"    ? 330
                    :                                 330; // URL
    const srcColW  = COL_W - valueColW - 8;

    // Table header row
    ensureSpace(18);
    drawRect(MARGIN, y - 18, COL_W, 18, rgb(0.88, 0.91, 0.97));
    const colHeader = (sectionType === "MD5" || sectionType === "SHA1" || sectionType === "SHA256" || sectionType === "SHA512")
      ? "Hash"
      : "Indicator";
    text(colHeader, MARGIN + 4, y - 13, { size: 8.5, font: fontBold, color: COLORS.tableHeader });
    text("Source Article", MARGIN + valueColW + 8, y - 13, { size: 8.5, font: fontBold, color: COLORS.tableHeader });
    y -= 18;

    for (let i = 0; i < iocs.length; i++) {
      const ioc = iocs[i];
      ensureSpace(18);
      const rowColor = i % 2 === 0 ? COLORS.tableRow1 : COLORS.tableRow2;
      drawRect(MARGIN, y - 16, COL_W, 16, rowColor);
      text(ioc.hash, MARGIN + 4, y - 11, {
        size: 7.5,
        font: fontMono,
        color: COLORS.text,
        maxWidth: valueColW - 8,
      });
      text(ioc.articleTitle, MARGIN + valueColW + 8, y - 11, {
        size: 8,
        color: COLORS.muted,
        maxWidth: srcColW - 8,
      });
      y -= 16;
    }
    y -= 10;
  }

  // ── Article coverage ──
  ensureSpace(30);
  y -= 8;
  drawRect(MARGIN, y - 20, COL_W, 20, COLORS.tableHeader);
  text(`ARTICLES SCANNED  (${results.length} total)`, MARGIN + 8, y - 14, { size: 10, font: fontBold, color: COLORS.headerText });
  y -= 20;

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    ensureSpace(16);
    const rowColor = i % 2 === 0 ? COLORS.tableRow1 : COLORS.tableRow2;
    drawRect(MARGIN, y - 14, COL_W, 14, rowColor);
    const badge = r.error ? "ERR" : r.iocs.length > 0 ? `${r.iocs.length} IOC${r.iocs.length > 1 ? "s" : ""}` : "—";
    const badgeColor = r.error ? COLORS.red : r.iocs.length > 0 ? COLORS.green : COLORS.muted;
    text(badge, MARGIN + 4, y - 10, { size: 7.5, font: fontBold, color: badgeColor });
    text(r.title, MARGIN + 44, y - 10, { size: 8, color: COLORS.text, maxWidth: COL_W - 48 });
    y -= 14;
  }

  // ── Footer on every page ──
  const pageCount = doc.getPageCount();
  for (let i = 0; i < pageCount; i++) {
    const pg = doc.getPage(i);
    pg.drawText(`PAI IOC Reporter  ·  Page ${i + 1} of ${pageCount}  ·  ${dateStr}`, {
      x: MARGIN, y: 18, size: 7.5, font: fontRegular, color: COLORS.muted,
    });
  }

  return await doc.save();
}

// ─── Email (Gmail SMTP) ───────────────────────────────────────────────────────

async function sendReport(
  pdfBytes: Uint8Array,
  iocCount: number,
  runDate: Date,
  config: Record<string, string>
): Promise<void> {
  const gmailUser = config.GMAIL_USER || DEFAULT_FROM;
  const appPassword = config.GMAIL_APP_PASSWORD;

  if (!appPassword) {
    console.error(`
ERROR: GMAIL_APP_PASSWORD is not set.

Gmail requires an App Password (not your regular login password).
To set one up:
  1. Go to https://myaccount.google.com/apppasswords
     (Requires 2-Step Verification to be enabled on your Google account)
  2. Select app: "Mail", device: "Other" → name it "IOC Reporter" → Generate
  3. Copy the 16-character password and add it to:

     ~/.config/PAI/ioc-reporter.env

     GMAIL_USER=albea.notifications@gmail.com
     GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx

Then run this script again.
`);
    process.exit(1);
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: gmailUser,
      pass: appPassword.replace(/\s+/g, ""), // strip spaces from "xxxx xxxx xxxx xxxx" format
    },
  });

  const to = config.TO_EMAIL || DEFAULT_TO;
  const dateLabel = runDate.toISOString().slice(0, 10);
  const subject = `[IOC Report] ${dateLabel} — ${iocCount} IOC${iocCount !== 1 ? "s" : ""} found`;

  const info = await transporter.sendMail({
    from: `IOC Reporter <${gmailUser}>`,
    to,
    subject,
    html: `
      <p>Daily IOC report from <strong>cybersecuritynews.com</strong> for <strong>${dateLabel}</strong>.</p>
      <p><strong>${iocCount} unique IOC${iocCount !== 1 ? "s" : ""}</strong> detected (FileHashes, Domains, URLs, IPs). See attached PDF for full details.</p>
      <p style="color:#888;font-size:12px;">Sent by PAI IOC Reporter · albea.notifications@gmail.com</p>
    `,
    attachments: [
      {
        filename: `ioc-report-${dateLabel}.pdf`,
        content: Buffer.from(pdfBytes),
        contentType: "application/pdf",
      },
    ],
  });

  console.log(`SMTP from:      ${gmailUser}`);
  console.log(`SMTP to:        ${to}`);
  console.log(`SMTP messageId: ${info.messageId}`);
  console.log(`SMTP accepted:  ${JSON.stringify(info.accepted)}`);
  console.log(`SMTP rejected:  ${JSON.stringify(info.rejected)}`);
  console.log(`SMTP response:  ${info.response}`);
}

// ─── Failure notification ───────────────────────────────────────────────────
//
// Called from csv-pusher.ts when main() throws. Sends a short alert so the
// pipeline failing silently in a log file is no longer possible. Reuses the
// same Gmail transport config as sendReport — no new credentials, no new
// recipient. If this itself throws, the caller catches and logs but does not
// mask the original pipeline error.
export async function sendFailureEmail(
  error: Error,
  source: string,
  logPath: string,
): Promise<void> {
  const config = loadEnv();
  const gmailUser = config.GMAIL_USER || DEFAULT_FROM;
  const appPassword = config.GMAIL_APP_PASSWORD;
  if (!appPassword) {
    console.error("[failure-email] GMAIL_APP_PASSWORD not set — cannot send failure alert");
    return;
  }
  const to = config.TO_EMAIL || DEFAULT_TO;
  const dateLabel = new Date().toISOString().slice(0, 10);
  const subject = `[IOC Pipeline FAILED] ${dateLabel} — ${source}`;
  const stack = (error.stack || error.message || String(error))
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: gmailUser, pass: appPassword.replace(/\s+/g, "") },
  });
  const info = await transporter.sendMail({
    from: `IOC Reporter <${gmailUser}>`,
    to,
    subject,
    html: `
      <p><strong>The IOC pipeline failed on ${dateLabel}.</strong></p>
      <p>Source: <code>${source}</code></p>
      <p>Error message:</p>
      <pre style="background:#f5f5f5;padding:8px;border-radius:4px;white-space:pre-wrap;">${stack}</pre>
      <p>Full log: <code>${logPath}</code></p>
      <p style="color:#888;font-size:12px;">Sent by PAI IOC Reporter · ${gmailUser}</p>
    `,
  });
  console.log(`[failure-email] sent to ${to}; messageId=${info.messageId}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const config = loadEnv();
  const runDate = new Date();

  console.log(`[${runDate.toISOString()}] IOC Reporter starting…`);

  // 1. Fetch homepage
  console.log("Fetching homepage…");
  const homeHtml = await fetchPage(BASE_URL);
  if (!homeHtml) {
    console.error("Failed to fetch cybersecuritynews.com homepage");
    process.exit(1);
  }

  // 2. Extract article URLs
  const articleUrls = extractArticleUrls(homeHtml);
  console.log(`Found ${articleUrls.length} article URLs`);

  if (articleUrls.length === 0) {
    console.error("No article URLs found — site structure may have changed");
    process.exit(1);
  }

  // 3. Scrape articles
  console.log(`Scraping ${articleUrls.length} articles (${CONCURRENCY} parallel)…`);
  const results = await scrapeAll(articleUrls);

  const totalIocs = new Set(results.flatMap(r => r.iocs.map(i => i.hash))).size;
  const articlesWithIocs = results.filter(r => r.iocs.length > 0);
  const breakdown = { MD5: 0, SHA1: 0, SHA256: 0, SHA512: 0, Domain: 0, URL: 0, IP: 0 } as Record<string, number>;
  const seenForBreakdown = new Set<string>();
  for (const r of results) for (const i of r.iocs) {
    if (seenForBreakdown.has(i.hash)) continue;
    seenForBreakdown.add(i.hash);
    breakdown[i.type]++;
  }
  console.log(`Found ${totalIocs} unique IOCs in ${articlesWithIocs.length} articles — breakdown: ${JSON.stringify(breakdown)}`);

  // 4. Build PDF
  console.log("Generating PDF…");
  const pdfBytes = await buildPDF(results, runDate);
  console.log(`PDF size: ${(pdfBytes.length / 1024).toFixed(1)} KB`);

  // 5. Send email
  if (process.env.SAVE_PDF) {
    writeFileSync(process.env.SAVE_PDF, Buffer.from(pdfBytes));
    console.log(`PDF saved to ${process.env.SAVE_PDF} (skipping email — SAVE_PDF set)`);
    await closeBrowser();
    return;
  }
  console.log("Sending email via Gmail SMTP…");
  await sendReport(pdfBytes, totalIocs, runDate, config);

  // 6. Clean up browser
  await closeBrowser();

  console.log("Done.");
}

// Only run as entry point — prevents email send when this file is imported as a library.
if (import.meta.main) {
  main().catch(async err => {
    await closeBrowser();
    console.error("Fatal:", err);
    process.exit(1);
  });
}
