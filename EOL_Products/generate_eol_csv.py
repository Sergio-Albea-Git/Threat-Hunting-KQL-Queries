#!/usr/bin/env python3
"""
Generate an End-of-Life (EOL) reference CSV from https://endoflife.date/
for the os / database / app product categories, aligned to Microsoft
Defender XDR advanced-hunting field names (SoftwareVendor, SoftwareName,
ProductCodeCpe) so it can be joined against DeviceTvmSoftwareInventory
and DeviceInfo to find products approaching or past end of life.

Data source: https://endoflife.date/  (v1 API)
Re-runnable: no manual edits required. Just: python3 generate_eol_csv.py
"""
import csv, json, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

API = "https://endoflife.date/api/v1"
CATEGORIES = ["os", "database", "app"]        # Operating systems, Databases, Applications
OUT = "eol_products.csv"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "eol-defender-xdr/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def cpe_parts(identifiers):
    """Return (cpe23, vendor, product) from endoflife identifiers, preferring cpe:2.3."""
    cpe23 = ""
    for ident in identifiers or []:
        if ident.get("type") == "cpe" and ident.get("id", "").startswith("cpe:2.3:"):
            cpe23 = ident["id"]; break
    if not cpe23:  # fall back to any cpe
        for ident in identifiers or []:
            if ident.get("type") == "cpe":
                cpe23 = ident["id"]; break
    vendor = product = ""
    if cpe23.startswith("cpe:2.3:"):
        f = cpe23.split(":")
        if len(f) >= 5:
            vendor, product = f[3], f[4]        # cpe:2.3:part:vendor:product:...
    return cpe23, vendor, product

def product_rows(category, slug):
    d = get(f"{API}/products/{slug}")["result"]
    cpe23, vendor, product = cpe_parts(d.get("identifiers"))
    aliases = ";".join(d.get("aliases") or [])
    rows = []
    for rel in d.get("releases", []):
        latest = (rel.get("latest") or {}).get("name") or ""
        rows.append({
            "category": category,
            "product_id": d["name"],
            "product": d.get("label", d["name"]),
            "release": rel.get("label", rel.get("name", "")),
            "release_date": rel.get("releaseDate") or "",
            "eol_date": rel.get("eolFrom") or "",
            "is_eol": rel.get("isEol"),
            "is_maintained": rel.get("isMaintained"),
            "latest_version": latest,
            "cpe": cpe23,
            "defender_vendor": vendor,           # -> DeviceTvmSoftwareInventory.SoftwareVendor
            "defender_softwarename": product,    # -> DeviceTvmSoftwareInventory.SoftwareName
            "aliases": aliases,
        })
    return rows

def main():
    tasks = []
    for cat in CATEGORIES:
        listing = get(f"{API}/categories/{cat}")["result"]
        for p in listing:
            tasks.append((cat, p["name"]))
    print(f"Fetching {len(tasks)} products across {CATEGORIES} ...", file=sys.stderr)
    all_rows = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for rows in ex.map(lambda t: product_rows(*t), tasks):
            all_rows.extend(rows)
    cols = ["category","product_id","product","release","release_date","eol_date",
            "is_eol","is_maintained","latest_version","cpe","defender_vendor",
            "defender_softwarename","aliases"]
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in sorted(all_rows, key=lambda x: (x["category"], x["product"], x["release"])):
            w.writerow(r)
    print(f"Wrote {OUT}: {len(all_rows)} rows, {len(tasks)} products", file=sys.stderr)

if __name__ == "__main__":
    main()
