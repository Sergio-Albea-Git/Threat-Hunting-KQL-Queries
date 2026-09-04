# End-of-Life (EOL) reference → Microsoft Defender XDR mapping

This reference is built using **[endoflife.date](https://endoflife.date/)** (its public
v1 API). It provides a single CSV, [`eol_products.csv`](./eol_products.csv), listing the
end-of-life / end-of-support dates for every product in three categories:

- **Operating systems** (`os`)
- **Databases** (`database`)
- **Applications** (`app`)

The goal is to **join this data against your Defender XDR inventory in KQL** so you can see
which installed products (and OS versions) are already past end-of-life or approaching it.

> Scope note: only the `os`, `database`, and `app` categories are included for now.
> endoflife.date also has `framework`, `lang`, `service`, `server-app`, `device`, and
> `standard` — those are intentionally left out until needed.

Ready-to-run queries live in [`eol_products.kql`](./eol_products.kql). Each query there is
**self-contained** (it declares its own `let eol = externaldata(...)`), so you can copy a
single block into Advanced Hunting and run it as-is — no shared setup between blocks.

## What's in the CSV

One row **per product release/version** (a product like Windows has many rows, one per
version, because each version has its own EOL date). Current snapshot:
**2,645 rows across 155 products** (`os` 1171 · `app` 1043 · `database` 431).

| Column | Meaning | Defender XDR equivalent |
| --- | --- | --- |
| `category` | `os`, `database`, or `app` | — |
| `product_id` | endoflife.date slug (e.g. `windows`, `sql-server`) | — |
| `product` | Human label (e.g. `Microsoft Windows`) | — |
| `release` | The version/cycle (e.g. `10 22H2`, `2019`) | `SoftwareVersion` / `OSVersion` |
| `release_date` | When that version was released | — |
| `eol_date` | **End-of-life / end-of-support date** for that version | `EndOfSupportDate` |
| `is_eol` | `True` if that version is already EOL today | `EndOfSupportStatus` |
| `is_maintained` | `True` if still maintained | — |
| `latest_version` | Latest patch version in that release | — |
| `cpe` | CPE 2.3 identifier from endoflife.date | **`ProductCodeCpe`** (best join key) |
| `defender_vendor` | Vendor parsed from the CPE (e.g. `microsoft`) | **`SoftwareVendor`** |
| `defender_softwarename` | Product parsed from the CPE (e.g. `windows`, `chrome`) | **`SoftwareName`** |
| `aliases` | Other names endoflife.date knows this product by | — |

`defender_vendor` and `defender_softwarename` are derived from the CPE
(`cpe:2.3:part:vendor:product:...`), which is how Defender's Threat & Vulnerability
Management normalizes `SoftwareVendor` / `SoftwareName`. That makes them a good starting
point for matching — **but see the caveat below.**

## How to use it in KQL

The CSV is fetched directly from this repo with `externaldata`, so no watchlist upload is
needed. Raw URL:

```
https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/main/EOL_Products/eol_products.csv
```

### 1. Applications & databases — matched to how Defender names software
The full, ready-to-run query is **QUERY B** in [`eol_products.kql`](./eol_products.kql). It is
built from a real `DeviceTvmSoftwareInventory` export, because Defender does **not** store a
clean product name — it stores a lower-case, CPE-style token with qualifiers:

| What Defender stores (`SoftwareName`) | endoflife token | Note |
| --- | --- | --- |
| `firefox`, `firefox_for_mac` | `firefox` | `_for_mac` suffix is stripped |
| `firefox_esr`, `mysql_router_8.0` | `firefox`, `mysql` | matched by `token_` prefix |
| `acrobat_reader_dc_(x64)`, `blender_(user)` | `acrobat`, `blender` | `_(x64)` / `_(user)` stripped |
| `office_16_click-to-run_licensing_component` | `office` | Office sub-components fold to `office` |

Because most products ship many releases (each with its own EOL date), matching on
**name alone is not enough** — it would flag every version as EOL. QUERY B also maps the
installed `SoftwareVersion` to the right endoflife release:

- **Generic** — compare the release to the version's `major` (`firefox 128`, `chrome 128`,
  `postgresql 16`) or `major.minor` (`mysql 8.0`, `mariadb 10.5`, `libreoffice 24.8`).
- **Microsoft is special** — `SoftwareVersion` is an internal build, not the year. QUERY B maps
  the build major to the release: SQL Server `13.x → 2016`, `15.x → 2019`, `16.x → 2022`;
  Office `15.x → 2013`. **Office `16.x` = 2016/2019/2021/365 at once and cannot be told apart
  from the build**, so those rows are intentionally left unmatched instead of guessed.

### 2. Exact match on CPE (most precise)
When Defender populates `ProductCodeCpe`, match on the CPE prefix instead:

```kql
DeviceTvmSoftwareInventory
| where isnotempty(ProductCodeCpe) and ProductCodeCpe != "not available"
| extend cpe_key = strcat(split(ProductCodeCpe, ":")[3], ":", split(ProductCodeCpe, ":")[4])
| join kind=inner (
    eol | extend cpe_key = strcat(defender_vendor, ":", defender_softwarename)
) on cpe_key
```

### 3. Operating systems — join against DeviceInfo
Defender represents the OS across `OSPlatform`, `OSVersion` and `OSVersionInfo`, and each
platform encodes its "release" differently. The `os` rows are matched by building a
normalized `os_key` on both sides (see `eol_products.kql`, **CASE 4–6**):

| Defender `OSPlatform` | Release comes from | endoflife.date `os` release | Example key |
| --- | --- | --- | --- |
| `Windows10` / `Windows11` | `OSVersionInfo` (`22H2`, `24H2`, `1607`) — `OSVersion` is always `10.0` | `10 22H2`, `11 24H2 (W)` (consumer/GA channel) | `win\|11 24H2` |
| `WindowsServer2019` / `2022` / `2016` | the year in `OSPlatform` | `Windows Server 2022 (LTSC)` | `winsrv\|2022` |
| `macOS` | major of `OSVersion` (`26.6.2` → `26`) | `macOS 26 (Tahoe)`, `macOS 15 (Sequoia)` | `mac\|26` |
| `iOS` | major of `OSVersion` (`26.6` → `26`) | `26`, `18` | `ios\|26` |
| `Android` | major of `OSVersion` (`15.0` → `15`) | `15 'Vanilla Ice Cream'` | `android\|15` |

```kql
// abridged — full versions (status / past-EOL / upcoming) are in eol_products.kql
DeviceInfo
| summarize arg_max(Timestamp, OSVersion, OSVersionInfo) by DeviceId, DeviceName, OSPlatform
| extend os_key = case(
    OSPlatform startswith "WindowsServer", strcat("winsrv|", extract(@"(\d{4})", 1, OSPlatform)),
    OSPlatform startswith "Windows",       strcat("win|", extract(@"(\d+)$", 1, OSPlatform), " ", OSVersionInfo),
    OSPlatform =~ "macOS",                 strcat("mac|", tostring(split(OSVersion, ".")[0])),
    OSPlatform =~ "iOS",                   strcat("ios|", tostring(split(OSVersion, ".")[0])),
    OSPlatform =~ "Android",               strcat("android|", tostring(split(OSVersion, ".")[0])),
    "")
// | join to the normalized os rows of eol_products.csv on os_key — see CASE 4
```

> Windows client rows exist per servicing channel — consumer/GA `(W)`, Enterprise/Education
> `(E)`, and `LTS`/`IoT`. CASE 4–6 keep the **consumer `(W)`/GA** row as the default; if your
> fleet is Enterprise or LTSC, drop the `!contains "(E)"` / `LTS` filters to use those dates.
> Windows Server uses the **LTSC** channel. macOS versions before 11 all report `OSVersion`
> `10.x`, so they collapse to `mac|10` — irrelevant for a modern fleet but worth knowing.

## ⚠️ Name-matching caveat

The `defender_vendor` / `defender_softwarename` columns are a **best-effort starting
point**, not a guaranteed match:

- Roughly a third of rows have **no CPE** in endoflife.date — for those, `defender_*`
  columns are blank and you must map them by hand against your own data.
- Defender's `SoftwareName` sometimes differs from the CPE product token (edition suffixes,
  spacing, `_` vs `-`).
- Validate against reality first:
  ```kql
  DeviceTvmSoftwareInventory | distinct SoftwareVendor, SoftwareName | order by SoftwareVendor
  ```
  then reconcile the handful that don't line up.

## Regenerating / updating the data

The CSV goes stale as vendors publish new EOL dates. Regenerate any time:

```bash
python3 generate_eol_csv.py   # rewrites eol_products.csv from the live endoflife.date API
```

No arguments, no manual edits. To change which categories are included, edit the
`CATEGORIES` list at the top of the script.

## Source & credit

All lifecycle data comes from **[endoflife.date](https://endoflife.date/)** and its
contributors, via the `https://endoflife.date/api/v1` API. This folder only reshapes that
data into a Defender-XDR-friendly CSV.
