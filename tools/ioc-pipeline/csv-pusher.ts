#!/usr/bin/env bun
/**
 * IOC CSV Pusher
 *
 * Scrapes cybersecuritynews.com homepage, extracts IOCs + each article's
 * publication date, builds a MISP-friendly CSV with a 5-day rolling window
 * (by article publication date), and pushes it to a target GitHub repo
 * subdirectory.
 *
 * Reads from ~/.config/PAI/ioc-reporter.env:
 *   GITHUB_TOKEN         — fine-grained PAT with Contents: Read/Write on the target repo
 *   GITHUB_REPO          — owner/name, e.g. Sergio-Albea-Git/Threat-Hunting-KQL-Queries
 *   GITHUB_TARGET_PATH   — subdirectory within the repo, e.g. Daily-IOCReportsCollection
 *   GITHUB_BRANCH        — usually "main"
 *
 * Usage:
 *   bun csv-pusher.ts
 *
 * Local working clone lives at ~/.local/share/pai/iocfeed/<repo-name>.
 * Token never persists in .git/config — passed per-command via http.extraheader.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join, dirname } from "path";
import { execSync, type ExecSyncOptions } from "child_process";

import {
  fetchPage,
  extractArticleUrls,
  scrapeAll,
  closeBrowser,
  isBenignFilename,
  isAllowlistedDomainExported,
  isCloudflareIP,
  sendFailureEmail,
  type ArticleResult,
  type IOC,
} from "./ioc-reporter.ts";

import { scrapeRansomwareLive } from "./ransomware-live-source.ts";

// ─── Config ──────────────────────────────────────────────────────────────────

const ENV_FILE = join(homedir(), ".config", "PAI", "ioc-reporter.env");
const BASE_URL = "https://cybersecuritynews.com";
const CLONE_PARENT = join(homedir(), ".local", "share", "pai", "iocfeed");
const WINDOW_DAYS = 30;
const CSV_FILE_NAME = "iocs.csv";

// Per-article cache: maps article URL → { publishedAt, title, scrapedAt, iocs }.
// Lets daily runs avoid re-scraping articles we've already processed within
// the window — only NEW articles get fetched. Entries past the window get GC'd.
const STATE_FILE_CSN = join(CLONE_PARENT, "csn-articles-state.json");

// WordPress REST API pagination knobs.
const WP_PAGE_SIZE = 100;
const WP_MAX_PAGES = 12;

function loadEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  if (existsSync(ENV_FILE)) {
    for (const line of readFileSync(ENV_FILE, "utf8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq < 0) continue;
      const k = t.slice(0, eq).trim();
      let v = t.slice(eq + 1).trim();
      // strip wrapping quotes if present
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      env[k] = v;
    }
  }
  for (const k of ["GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_TARGET_PATH", "GITHUB_BRANCH"]) {
    if (process.env[k]) env[k] = process.env[k]!;
  }
  return env;
}

// ─── CSV helpers ─────────────────────────────────────────────────────────────

const CSV_HEADER = "type,value,source_url,source_title,article_published_at,first_seen";

function csvEscape(v: string): string {
  if (/[",\n\r]/.test(v)) {
    return `"${v.replace(/"/g, '""')}"`;
  }
  return v;
}

function iocTypeToMisp(t: IOC["type"]): string {
  // MISP convention: lowercase. Special-case CamelCase types that need
  // an underscore in the canonical form so they line up with other sources
  // (e.g. ransomware-live-source emits "registry_key" not "registrykey").
  if (t === "RegistryKey") return "registry_key";
  return t.toLowerCase();
}

interface CsvRow {
  type: string;
  value: string;
  source_url: string;
  source_title: string;
  article_published_at: string; // ISO 8601 or ""
  first_seen: string;           // ISO 8601
}

function rowsToCSV(rows: CsvRow[]): string {
  const lines = [CSV_HEADER];
  // Stable ordering: by type, then value — diff-friendly across runs
  const sorted = [...rows].sort((a, b) =>
    a.type !== b.type ? a.type.localeCompare(b.type) : a.value.localeCompare(b.value)
  );
  for (const r of sorted) {
    lines.push([
      csvEscape(r.type),
      csvEscape(r.value),
      csvEscape(r.source_url),
      csvEscape(r.source_title),
      csvEscape(r.article_published_at),
      csvEscape(r.first_seen),
    ].join(","));
  }
  return lines.join("\n") + "\n";
}

function resultsToRows(results: ArticleResult[], firstSeen: string): CsvRow[] {
  const rows: CsvRow[] = [];
  const seen = new Set<string>(); // dedupe by value alone — keep first occurrence
  for (const r of results) {
    for (const ioc of r.iocs) {
      const type = iocTypeToMisp(ioc.type);
      const key = ioc.hash.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({
        type,
        value: ioc.hash,
        source_url: r.url,
        source_title: r.title,
        article_published_at: r.publishedAt ?? "",
        first_seen: r.scrapedAt ?? firstSeen,
      });
    }
  }
  return rows;
}

function filterWindow(rows: CsvRow[]): CsvRow[] {
  const cutoff = Date.now() - WINDOW_DAYS * 24 * 3600 * 1000;
  return rows.filter(r => {
    if (!r.article_published_at) return true; // no date → include
    const t = Date.parse(r.article_published_at);
    if (isNaN(t)) return true;
    return t >= cutoff;
  });
}

/** Drop rows for IOCs that match the trusted/legitimate criteria —
 *  applied at CSV-build time as a defense-in-depth layer over the
 *  extraction-time filter. Means denylist/allowlist updates take effect
 *  immediately for cached state without needing to rescrape anything. */
function filterBenign(rows: CsvRow[]): { kept: CsvRow[]; dropped: Record<string, number> } {
  const dropped: Record<string, number> = {};
  const kept: CsvRow[] = [];
  for (const r of rows) {
    let dropReason: string | null = null;
    if (r.type === "filename" && isBenignFilename(r.value)) {
      dropReason = "benign_filename";
    } else if (r.type === "domain" && isAllowlistedDomainExported(r.value.toLowerCase())) {
      dropReason = "allowlisted_domain";
    } else if (r.type === "url") {
      try {
        const host = new URL(r.value).hostname.toLowerCase();
        if (isAllowlistedDomainExported(host)) dropReason = "url_allowlisted_host";
      } catch { /* unparseable URL — keep */ }
    } else if (r.type === "ip" && isCloudflareIP(r.value)) {
      dropReason = "cloudflare_ip";
    }
    if (dropReason) {
      dropped[dropReason] = (dropped[dropReason] ?? 0) + 1;
      continue;
    }
    kept.push(r);
  }
  return { kept, dropped };
}

// ─── Article state file ──────────────────────────────────────────────────────

interface CachedArticle {
  publishedAt: string; // ISO 8601
  title: string;
  scrapedAt: string;   // ISO 8601 — when WE last fetched it
  iocs: IOC[];
}
type CsnState = Record<string, CachedArticle>;

function loadCsnState(): CsnState {
  if (!existsSync(STATE_FILE_CSN)) return {};
  try {
    const parsed = JSON.parse(readFileSync(STATE_FILE_CSN, "utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as CsnState;
    }
    console.warn(`[csn-state] file shape invalid, starting fresh`);
  } catch (e) {
    console.warn(`[csn-state] corrupted (${(e as Error).message}), starting fresh`);
  }
  return {};
}

function saveCsnState(s: CsnState): void {
  mkdirSync(dirname(STATE_FILE_CSN), { recursive: true });
  writeFileSync(STATE_FILE_CSN, JSON.stringify(s, null, 2));
}

// ─── WordPress REST API discovery ────────────────────────────────────────────

interface DiscoveredArticle { link: string; publishedAt: string }

async function discoverArticlesViaWPAPI(daysBack: number): Promise<DiscoveredArticle[]> {
  const after = new Date(Date.now() - daysBack * 24 * 3600 * 1000).toISOString();
  const found: DiscoveredArticle[] = [];
  for (let page = 1; page <= WP_MAX_PAGES; page++) {
    const url = `${BASE_URL}/wp-json/wp/v2/posts?per_page=${WP_PAGE_SIZE}&page=${page}` +
                `&after=${encodeURIComponent(after)}&orderby=date&order=desc` +
                `&_fields=link,date_gmt,date`;
    let res: Response;
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    } catch (e) {
      console.warn(`[wp-api] page ${page} request failed: ${(e as Error).message}`);
      break;
    }
    // WP returns 400 "rest_post_invalid_page_number" once we go past the last page
    if (res.status === 400 || res.status === 404) break;
    if (!res.ok) {
      console.warn(`[wp-api] page ${page} HTTP ${res.status}`);
      break;
    }
    const posts = (await res.json()) as Array<{ link?: string; date?: string; date_gmt?: string }>;
    if (!Array.isArray(posts) || posts.length === 0) break;
    for (const p of posts) {
      if (!p.link) continue;
      const raw = p.date_gmt ? p.date_gmt + "Z" : (p.date ?? "");
      const iso = raw ? new Date(raw).toISOString() : "";
      if (!iso) continue;
      found.push({ link: p.link.replace(/\/$/, ""), publishedAt: iso });
    }
    if (posts.length < WP_PAGE_SIZE) break; // last page
  }
  console.log(`[wp-api] discovered ${found.length} articles in last ${daysBack}d`);
  return found;
}

// ─── Git operations (token via per-command http.extraheader) ─────────────────

function gitArgs(token: string): string[] {
  // CRITICAL: token only in process memory, not in .git/config.
  // GitHub git smart-HTTP requires Basic auth with username "x-access-token",
  // not Bearer (Bearer works for REST API but not git transport).
  const basic = Buffer.from(`x-access-token:${token}`).toString("base64");
  return ["-c", `http.extraheader=Authorization: Basic ${basic}`];
}

function run(cmd: string, args: string[], opts: ExecSyncOptions = {}): string {
  const argStr = args.map(a => /[\s"']/.test(a) ? `'${a.replace(/'/g, "'\\''")}'` : a).join(" ");
  return execSync(`${cmd} ${argStr}`, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts }).toString();
}

function ensureClone(repo: string, branch: string, token: string): string {
  const repoName = repo.split("/")[1];
  mkdirSync(CLONE_PARENT, { recursive: true });
  const clonePath = join(CLONE_PARENT, repoName);

  if (existsSync(join(clonePath, ".git"))) {
    console.log(`Clone exists at ${clonePath} — fetching latest…`);
    run("git", [...gitArgs(token), "-C", clonePath, "fetch", "origin", branch]);
    run("git", ["-C", clonePath, "checkout", branch]);
    run("git", [...gitArgs(token), "-C", clonePath, "reset", "--hard", `origin/${branch}`]);
  } else {
    console.log(`Cloning ${repo} → ${clonePath}…`);
    // Use --no-checkout to avoid LFS hooks if any; checkout after.
    run("git", [...gitArgs(token), "clone", "--depth", "1", "--branch", branch,
                `https://github.com/${repo}.git`, clonePath]);
  }
  return clonePath;
}

function commitAndPush(clonePath: string, relPath: string, branch: string, token: string, summary: string): boolean {
  // Configure local-only identity (does not touch global git config)
  run("git", ["-C", clonePath, "config", "user.email", "albea.notifications@gmail.com"]);
  run("git", ["-C", clonePath, "config", "user.name",  "PAI IOC Watcher"]);

  // Stage and check if there's actually a diff vs HEAD
  run("git", ["-C", clonePath, "add", relPath]);
  let staged: string;
  try {
    staged = run("git", ["-C", clonePath, "diff", "--cached", "--name-only"]).trim();
  } catch {
    staged = "";
  }
  if (!staged) {
    console.log("No changes vs remote — skipping commit/push.");
    return false;
  }
  console.log(`Staged: ${staged}`);
  run("git", ["-C", clonePath, "commit", "-m", summary]);
  console.log("Pushing…");
  run("git", [...gitArgs(token), "-C", clonePath, "push", "origin", branch]);
  return true;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const env = loadEnv();
  const TOKEN  = env.GITHUB_TOKEN;
  const REPO   = env.GITHUB_REPO;
  const TARGET = env.GITHUB_TARGET_PATH || "";
  const BRANCH = env.GITHUB_BRANCH || "main";

  if (!TOKEN || !REPO) {
    console.error("ERROR: GITHUB_TOKEN and GITHUB_REPO must be set in env.");
    process.exit(1);
  }

  const runDate = new Date();
  const firstSeen = runDate.toISOString();
  console.log(`[${firstSeen}] IOC CSV Pusher starting…`);
  console.log(`Target: ${REPO}/${TARGET}/${CSV_FILE_NAME} on branch ${BRANCH}`);

  try {
    // 1) Discover article URLs via WP REST API (preferred — gives publishedAt
    //    directly without scraping HTML) and as a safety net the homepage list.
    let wpArticles: DiscoveredArticle[] = [];
    try {
      wpArticles = await discoverArticlesViaWPAPI(WINDOW_DAYS);
    } catch (e) {
      console.warn(`[wp-api] failed entirely (${(e as Error).message}), homepage only`);
    }

    console.log("Fetching homepage for fallback URL list…");
    const home = await fetchPage(BASE_URL);
    const homeUrls = home ? extractArticleUrls(home) : [];
    console.log(`Homepage has ${homeUrls.length} article URLs`);

    // Merge: every WP-discovered URL + any homepage URL not already known.
    // Homepage URLs without an API match get publishedAt = now (will be refined
    // from extracted metadata if/when we scrape them).
    const discoveredMap = new Map<string, DiscoveredArticle>();
    for (const a of wpArticles) discoveredMap.set(a.link, a);
    for (const u of homeUrls) {
      if (!discoveredMap.has(u)) discoveredMap.set(u, { link: u, publishedAt: firstSeen });
    }
    const discovered = [...discoveredMap.values()];
    console.log(`Total discovered URLs (WP+homepage merged): ${discovered.length}`);

    // 2) Load article state and figure out which URLs we actually need to scrape
    const state = loadCsnState();
    const stateBefore = Object.keys(state).length;
    console.log(`Article state entries (before): ${stateBefore}`);

    const cutoffMs = Date.now() - WINDOW_DAYS * 24 * 3600 * 1000;
    const newUrls: string[] = [];
    for (const d of discovered) {
      // Retry entries previously cached as "Fetch failed" — a failed scrape
      // (HTTP error / timeout / CDN cold cache) shouldn't poison the cache
      // forever. Successful 0-IOC scrapes have a real title and stay cached.
      if (state[d.link] && state[d.link].title !== "Fetch failed") continue;
      const t = Date.parse(d.publishedAt);
      if (!isNaN(t) && t < cutoffMs) continue;              // outside window
      newUrls.push(d.link);
    }
    console.log(`URLs new (not in cache, within window): ${newUrls.length}`);

    // 3) Scrape the new ones (existing scrapeAll: Playwright + concurrency=4)
    if (newUrls.length > 0) {
      console.log(`Scraping ${newUrls.length} new articles…`);
      const scraped = await scrapeAll(newUrls);
      const withDate = scraped.filter(r => r.publishedAt).length;
      console.log(`Articles with detected publish date: ${withDate}/${scraped.length}`);
      // Persist every scraped article (including 0-IOC ones, so we don't refetch)
      for (const r of scraped) {
        const fromApi = discoveredMap.get(r.url)?.publishedAt;
        state[r.url] = {
          publishedAt: r.publishedAt ?? fromApi ?? firstSeen,
          title: r.title,
          scrapedAt: firstSeen,
          iocs: r.iocs,
        };
      }
    } else {
      console.log("No new articles to scrape — state is up to date.");
    }

    // 4) GC: drop state entries whose publishedAt is past the window
    let gcCount = 0;
    for (const url of Object.keys(state)) {
      const t = Date.parse(state[url].publishedAt);
      if (isNaN(t) || t < cutoffMs) {
        delete state[url];
        gcCount++;
      }
    }
    console.log(`State GC: ${gcCount} entries dropped (publishedAt past window)`);
    saveCsnState(state);
    console.log(`Article state entries (after): ${Object.keys(state).length}`);

    // 5a) Build rows from the FULL state (not just this run's scrape)
    const stateResults: ArticleResult[] = Object.entries(state).map(([url, e]) => ({
      url, title: e.title, iocs: e.iocs, publishedAt: e.publishedAt, scrapedAt: e.scrapedAt,
    }));
    const csnRowsAll = resultsToRows(stateResults, firstSeen);
    const csnWindowed = filterWindow(csnRowsAll);
    const csnFiltered = filterBenign(csnWindowed);
    const csnRows = csnFiltered.kept;
    console.log(`cybersecuritynews IOCs: ${csnRowsAll.length} → ${csnWindowed.length} (after ${WINDOW_DAYS}d window) → ${csnRows.length} (after benign filter; dropped ${JSON.stringify(csnFiltered.dropped)})`);

    // 5b) Pull ransomware.live IOCs (its own state file + window).
    //     Failures here must NOT block the cybersecuritynews push.
    let rlRows: Array<typeof csnRows[number]> = [];
    try {
      const fromRL = await scrapeRansomwareLive({ runIso: firstSeen, windowDays: WINDOW_DAYS });
      const rlFiltered = filterBenign(fromRL as Array<typeof csnRows[number]>);
      rlRows = rlFiltered.kept;
      if (Object.keys(rlFiltered.dropped).length > 0) {
        console.log(`[ransomware-live] benign filter dropped: ${JSON.stringify(rlFiltered.dropped)}`);
      }
    } catch (e) {
      console.error(`[ransomware-live] scrape failed (continuing with cybersecuritynews only): ${(e as Error).message}`);
    }

    // 2c) Merge + dedupe by value alone. cybersecuritynews wins on overlap to preserve article attribution.
    const seenMerge = new Set<string>();
    const rows: typeof csnRows = [];
    for (const r of csnRows) {
      const key = r.value.toLowerCase();
      if (seenMerge.has(key)) continue;
      seenMerge.add(key);
      rows.push(r);
    }
    let rlAdded = 0;
    for (const r of rlRows) {
      const key = r.value.toLowerCase();
      if (seenMerge.has(key)) continue;
      seenMerge.add(key);
      rows.push(r);
      rlAdded++;
    }
    console.log(`Combined: ${csnRows.length} csn + ${rlAdded} ransomware.live (post-dedupe) = ${rows.length} total`);

    const byType: Record<string, number> = {};
    for (const r of rows) byType[r.type] = (byType[r.type] || 0) + 1;
    console.log(`Breakdown:`, byType);

    if (rows.length === 0) {
      console.log("No IOCs to publish. Exiting without git changes.");
      return;
    }

    const csv = rowsToCSV(rows);

    // 3) Clone/fetch target repo
    const clonePath = ensureClone(REPO, BRANCH, TOKEN);
    const relPath = TARGET ? join(TARGET, CSV_FILE_NAME) : CSV_FILE_NAME;
    const absPath = join(clonePath, relPath);
    mkdirSync(dirname(absPath), { recursive: true });

    // 4) Write CSV
    writeFileSync(absPath, csv);
    console.log(`Wrote ${csv.length} bytes → ${relPath}`);

    // 5) Commit + push
    const summary = `chore(iocs): ${rows.length} IOCs (${csnRows.length} cybersecuritynews + ${rlAdded} ransomware.live, ${WINDOW_DAYS}-day window)`;
    const pushed = commitAndPush(clonePath, relPath, BRANCH, TOKEN, summary);

    if (pushed) {
      console.log("Push OK.");
      console.log(`View: https://github.com/${REPO}/blob/${BRANCH}/${relPath}`);
    }
  } finally {
    await closeBrowser();
  }
}

main().catch(async err => {
  console.error("FATAL:", err);
  const logPath = join(homedir(), ".claude", "MEMORY", "WORK", "csv-pusher.error.log");
  try {
    await sendFailureEmail(err instanceof Error ? err : new Error(String(err)), "csv-pusher", logPath);
  } catch (notifyErr) {
    console.error("[failure-email] send itself failed:", notifyErr);
  }
  process.exit(1);
});
