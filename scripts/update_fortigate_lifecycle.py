"""Maintainer script to refresh src/fwmigrate/source_reporting/lifecycle_data/fortigate_lifecycle.json.

Fetches FortiOS branch dates from endoflife.date and latest patch versions from
Fortinet's firmware RSS feed, and optionally merges a Fortinet Product Life Cycle
Hardware CSV export (Support Portal -> Product Life Cycle -> Hardware -> Export).
"""

from __future__ import annotations

import argparse
import csv
from datetime import date
import json
from pathlib import Path
import re
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fwmigrate.source_reporting.lifecycle import (  # noqa: E402
    _fetch_endoflife_branches,
    _fetch_fortinet_rss_latest,
    _merge_branches,
    normalize_fortigate_model,
)

CATALOG_PATH = (
    SRC_DIR / "fwmigrate" / "source_reporting" / "lifecycle_data" / "fortigate_lifecycle.json"
)


def _normalize_date(raw: str | None) -> str | None:
    text = str(raw or "").strip()
    if not text or text.lower() in ("n/a", "na", "none", "-", "tbd"):
        return None
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
    if m:
        return m.group(1)
    m_us = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", text)
    if m_us:
        mm, dd, yyyy = m_us.groups()
        return f"{yyyy}-{int(mm):02d}-{int(dd):02d}"
    return None


def _merge_hardware_csv(models: dict, csv_path: Path) -> int:
    updated = 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            norm_row = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
            product = (
                norm_row.get("product")
                or norm_row.get("model")
                or norm_row.get("hardware model")
                or ""
            )
            if not product or not re.search(r"(fortigate|fortiwifi|fg-|fgt|fwf)", product, re.IGNORECASE):
                continue
            key = normalize_fortigate_model(product)
            if not key:
                continue

            entry = models.setdefault(
                key,
                {
                    "display_name": f"FortiGate-{key[3:]}" if key.startswith("FG-") else key,
                    "eoo": None,
                    "lsed": None,
                    "eos": None,
                    "last_supported_firmware": "Active",
                    "is_vm": key == "FG-VM",
                },
            )
            eoo = _normalize_date(norm_row.get("end of order") or norm_row.get("eoo"))
            lsed = _normalize_date(norm_row.get("last service extension date") or norm_row.get("lsed"))
            eos = _normalize_date(norm_row.get("end of support") or norm_row.get("eos"))
            last_fw = (
                norm_row.get("last supported software version")
                or norm_row.get("last supported firmware")
                or norm_row.get("lssv")
                or ""
            )
            if eoo:
                entry["eoo"] = eoo
            if lsed:
                entry["lsed"] = lsed
            if eos:
                entry["eos"] = eos
            if last_fw:
                entry["last_supported_firmware"] = last_fw
            updated += 1
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh FortiGate lifecycle snapshot JSON.")
    parser.add_argument("--hardware-csv", type=Path, default=None, help="Optional Fortinet hardware lifecycle CSV export")
    parser.add_argument("--offline", action="store_true", help="Skip live HTTP fetches (only apply --hardware-csv)")
    args = parser.parse_args()

    if CATALOG_PATH.exists():
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    else:
        catalog = {"updated_at": "", "branches": {}, "models": {}}

    eol_data = None
    rss_data = None
    if not args.offline:
        try:
            eol_data = _fetch_endoflife_branches()
            print(f"Fetched {len(eol_data)} branches from endoflife.date")
        except Exception as exc:
            print(f"Warning: endoflife.date fetch failed: {exc}")
        try:
            rss_data = _fetch_fortinet_rss_latest()
            print(f"Fetched {len(rss_data)} branch latest versions from Fortinet RSS")
        except Exception as exc:
            print(f"Warning: Fortinet RSS fetch failed: {exc}")

    catalog["branches"] = _merge_branches(catalog.get("branches") or {}, eol_data, rss_data)
    models = catalog.setdefault("models", {})
    if args.hardware_csv:
        count = _merge_hardware_csv(models, args.hardware_csv)
        print(f"Merged {count} FortiGate rows from {args.hardware_csv}")

    catalog["updated_at"] = date.today().isoformat()
    CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_PATH.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {CATALOG_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
