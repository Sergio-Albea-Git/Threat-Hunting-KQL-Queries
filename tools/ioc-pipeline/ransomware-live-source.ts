#!/usr/bin/env bun
/**
 * Ransomware.live IOC source.
 *
 * Scrapes https://www.ransomware.live/ioc, normalizes types to MISP convention,
 * tracks first_seen per IOC in a persistent state file, and applies the same
 * 5-day rolling window the csv-pusher uses for cybersecuritynews.com.
 *
 * The HTML page exposes IOCs grouped by ransomware family but no per-IOC date,
 * so the window is anchored to "when WE first observed the value" (state file)
 * rather than a source-provided publication date.
 *
 * State file lives next to the clone parent:
 *   ~/.local/share/pai/iocfeed/ransomware-live-state.json
 *   { "<ioc value>": "<ISO 8601 first_seen>" }
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join, dirname } from "path";

const IOC_URL    = "https://www.ransomware.live/ioc";
const STATE_FILE = join(homedir(), ".local", "share", "pai", "iocfeed", "ransomware-live-state.json");
const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// Map ransomware.live label (case-insensitive) → MISP-style lowercase type.
const TYPE_MAP_RAW: Record<string, string> = {
  "Hash MD5":       "md5",
  "Hash SHA1":      "sha1",
  "Hash SHA256":    "sha256",
  "Hash SHA512":    "sha512",
  "IP":             "ip",
  "IP Address":     "ip",
  "Domain":         "domain",
  "URL":            "url",
  "Email":          "email",
  "Bitcoin":        "btc",
  "BTC":            "btc",
  "Bitcoin Wallet": "btc",
  "XMR Wallet":     "xmr",
  "Tox":            "tox",
  "Session":        "session",
  "Telegram":       "telegram",
  "Twitter":        "twitter",
  "FTP":            "ftp",
  "Registry Key":   "registry_key",
  "Mutex":          "mutex",
};
const TYPE_MAP: Record<string, string> = Object.fromEntries(
  Object.entries(TYPE_MAP_RAW).map(([k, v]) => [k.toLowerCase(), v]),
);

// Types that are mapped but intentionally omitted from the output feed.
// btc: Bitcoin wallet addresses — financial-intel value but rarely actionable
// in endpoint/network KQL hunts.
const EXCLUDED_TYPES = new Set<string>(["btc"]);

// Multi-line PGP key blocks are excluded — they don't fit one-line CSV usefully.

export interface RansomwareLiveRow {
  type: string;
  value: string;
  source_url: string;
  source_title: string;
  article_published_at: string; // always "" — ransomware.live doesn't expose per-IOC dates
  first_seen: string;           // ISO 8601; sourced from state file or set to runIso
}

interface State { [value: string]: string }  // value → first_seen ISO

// ─── State file ──────────────────────────────────────────────────────────────

function loadState(): State {
  if (!existsSync(STATE_FILE)) return {};
  try {
    const parsed = JSON.parse(readFileSync(STATE_FILE, "utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as State;
    console.warn(`[ransomware-live] state file shape invalid, starting fresh`);
    return {};
  } catch (e) {
    console.warn(`[ransomware-live] state file corrupted (${(e as Error).message}), starting fresh`);
    return {};
  }
}

function saveState(s: State): void {
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
}

// ─── HTML parsing ────────────────────────────────────────────────────────────

interface RawTuple { group: string; typeLabel: string; value: string }

function parseHtml(html: string): RawTuple[] {
  const out: RawTuple[] = [];
  // Each ransomware group is wrapped in: <div class="accordion-item group-item" data-name="<slug>" ...>
  const groupRe =
    /<div class="accordion-item group-item"\s+data-name="([^"]+)"[^>]*>([\s\S]*?)(?=<div class="accordion-item group-item"|<\/body>)/g;
  // Within a group, each IOC row is: <tr><td>...<code>label</code></td><td>...<code>value</code></td>
  const rowRe =
    /<tr>\s*<td>\s*(?:<i[^>]*><\/i>\s*)?<code>([^<]+)<\/code>\s*<\/td>\s*<td>\s*(?:<i[^>]*><\/i>\s*)?<code>([^<]+)<\/code>/g;

  let gm: RegExpExecArray | null;
  while ((gm = groupRe.exec(html)) !== null) {
    const group = gm[1].trim();
    const block = gm[2];
    rowRe.lastIndex = 0;
    let rm: RegExpExecArray | null;
    while ((rm = rowRe.exec(block)) !== null) {
      const value = rm[2].trim();
      if (/[\r\n]/.test(value)) continue; // skip multi-line (PGP blocks live in <pre><code>)
      out.push({ group, typeLabel: rm[1].trim(), value });
    }
  }
  return out;
}

// ─── Public entry ────────────────────────────────────────────────────────────

export interface ScrapeOptions {
  runIso: string;     // ISO 8601 timestamp used for "first_seen" of newly-observed values
  windowDays: number; // retention window — values whose first_seen is older are dropped
}

export async function scrapeRansomwareLive(opts: ScrapeOptions): Promise<RansomwareLiveRow[]> {
  console.log(`[ransomware-live] fetching ${IOC_URL}…`);
  const res = await fetch(IOC_URL, {
    headers: {
      "User-Agent":      USER_AGENT,
      "Accept-Language": "en-US,en;q=0.9",
      "Accept":          "text/html,application/xhtml+xml",
    },
  });
  if (!res.ok) {
    throw new Error(`ransomware.live HTTP ${res.status}`);
  }
  const html = await res.text();
  console.log(`[ransomware-live] HTML size: ${(html.length / 1024).toFixed(1)} KB`);

  const parsed = parseHtml(html);
  console.log(`[ransomware-live] parsed ${parsed.length} (group, type, value) tuples from HTML`);
  if (parsed.length < 100) {
    // Strong signal the layout changed or the page didn't load fully.
    console.warn(`[ransomware-live] WARNING: parsed only ${parsed.length} tuples — layout may have changed`);
  }

  const state = loadState();
  const stateBefore = Object.keys(state).length;

  const runMs = Date.parse(opts.runIso);
  const cutoff = runMs - opts.windowDays * 24 * 3600 * 1000;

  const rows: RansomwareLiveRow[] = [];
  const seenThisRun = new Set<string>(); // dedupe within scrape: same value under multiple groups → first wins
  const observedValuesThisRun = new Set<string>();
  const typeCounts: Record<string, number> = {};
  let unknownTypes = 0;
  let excludedTypeRows = 0;
  const unknownTypeSamples: Record<string, number> = {};

  for (const { group, typeLabel, value } of parsed) {
    observedValuesThisRun.add(value);
    const normType = TYPE_MAP[typeLabel.toLowerCase()];
    if (!normType) {
      unknownTypes++;
      unknownTypeSamples[typeLabel] = (unknownTypeSamples[typeLabel] || 0) + 1;
      continue;
    }
    if (EXCLUDED_TYPES.has(normType)) {
      excludedTypeRows++;
      continue;
    }
    // Dedupe by value alone — keep first occurrence regardless of type.
    const dedupKey = value.toLowerCase();
    if (seenThisRun.has(dedupKey)) continue;
    seenThisRun.add(dedupKey);

    let firstSeen = state[value];
    if (!firstSeen) {
      firstSeen = opts.runIso;
      state[value] = firstSeen;
    }

    const ts = Date.parse(firstSeen);
    if (!isNaN(ts) && ts < cutoff) {
      // Past retention window — drop the row AND remove the state entry.
      delete state[value];
      continue;
    }

    rows.push({
      type: normType,
      value,
      source_url:           `https://www.ransomware.live/group/${group}`,
      source_title:         `Ransomware.live - ${group}`,
      article_published_at: "",
      first_seen:           firstSeen,
    });
    typeCounts[normType] = (typeCounts[normType] || 0) + 1;
  }

  // Garbage-collect state entries for values that disappeared from the source
  // and whose first_seen is past the cutoff. Keeps the file small over time.
  for (const [v, fs] of Object.entries(state)) {
    if (observedValuesThisRun.has(v)) continue;
    const ts = Date.parse(fs);
    if (isNaN(ts) || ts < cutoff) {
      delete state[v];
    }
  }
  saveState(state);

  const stateAfter = Object.keys(state).length;
  console.log(`[ransomware-live] state entries: ${stateBefore} → ${stateAfter}`);
  console.log(`[ransomware-live] emit ${rows.length} rows (skipped ${unknownTypes} unknown-type, ${excludedTypeRows} excluded-type [${[...EXCLUDED_TYPES].join(",")}])`);
  console.log(`[ransomware-live] breakdown:`, typeCounts);
  if (unknownTypes > 0) {
    console.log(`[ransomware-live] unknown type labels seen:`, unknownTypeSamples);
  }

  return rows;
}
