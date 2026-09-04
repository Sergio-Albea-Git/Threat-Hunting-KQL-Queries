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

Ready-to-run queries live in [`eol_products.kql`](./eol_products.kql).

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

### 1. Applications & databases — join on vendor + name

```kql
// Devices running software that is already end-of-life
let eol = externaldata(category:string, product_id:string, product:string, release:string,
    release_date:string, eol_date:string, is_eol:string, is_maintained:string,
    latest_version:string, cpe:string, defender_vendor:string, defender_softwarename:string,
    aliases:string)
    [@"https://raw.githubusercontent.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/main/EOL_Products/eol_products.csv"]
    with (format="csv", ignoreFirstRecord=true);
DeviceTvmSoftwareInventory
| where isnotempty(SoftwareVendor) and isnotempty(SoftwareName)
| join kind=inner (
    eol
    | where isnotempty(defender_vendor) and todatetime(eol_date) < now()
) on $left.SoftwareVendor == $right.defender_vendor,
     $left.SoftwareName == $right.defender_softwarename
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion,
          eol_release=release, eol_date, latest_version
```

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
OS lifecycle is best matched on `OSPlatform` / `OSVersion`:

```kql
DeviceInfo
| summarize arg_max(Timestamp, OSPlatform, OSVersion) by DeviceId, DeviceName
// then join to the os rows of eol_products.csv on your normalized OS name/version
```

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
