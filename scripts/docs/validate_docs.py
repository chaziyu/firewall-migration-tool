from __future__ import annotations

import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "documentation"
METADATA = DOCS / "metadata" / "documents.yml"
VENDORS = DOCS / "metadata" / "vendors.yml"
ACTIVE_DIRS = (DOCS / "how-to", DOCS / "explanation", DOCS / "reference", DOCS / "decisions")
ALLOWED_STATUS = {"current", "draft", "deprecated", "archived"}
ALLOWED_TYPES = {"how-to", "explanation", "reference", "support-matrix", "decision", "archive"}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.md$")


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(path)
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _date(value: object) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _local_target(doc: Path, target: str) -> Path | None:
    target = target.strip().split("#", 1)[0].split("?", 1)[0]
    if not target or target.startswith(("http://", "https://", "mailto:", "tel:")):
        return None
    return (doc.parent / unquote(target)).resolve()


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    docs_meta = _load_yaml(METADATA).get("documents", {})
    vendor_meta = _load_yaml(VENDORS).get("vendors", {})

    required = {"title", "status", "document_type", "source_of_truth", "last_verified"}
    for rel, meta in docs_meta.items():
        path = ROOT / rel
        missing = required - set(meta or {})
        if missing:
            errors.append(f"{rel}: missing metadata keys {sorted(missing)}")
            continue
        if meta["status"] not in ALLOWED_STATUS:
            errors.append(f"{rel}: invalid status {meta['status']!r}")
        if meta["document_type"] not in ALLOWED_TYPES:
            errors.append(f"{rel}: invalid document_type {meta['document_type']!r}")
        if not path.exists():
            errors.append(f"{rel}: document does not exist")
            continue
        try:
            _date(meta["last_verified"])
        except ValueError:
            errors.append(f"{rel}: last_verified must be ISO YYYY-MM-DD")
        for source in meta.get("source_of_truth") or []:
            if str(source).startswith(("http://", "https://")):
                continue
            if not (ROOT / str(source)).exists():
                errors.append(f"{rel}: source_of_truth path does not exist: {source}")
        text = path.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(text):
            target = _local_target(path, raw_target)
            if target is not None and not target.exists():
                errors.append(f"{rel}: broken local link: {raw_target}")

    listed = {str((ROOT / rel).resolve()) for rel in docs_meta}
    for directory in ACTIVE_DIRS:
        if not directory.exists():
            continue
        for path in directory.rglob("*.md"):
            if path.name != "README.md" and not KEBAB_RE.match(path.name):
                errors.append(f"{path.relative_to(ROOT)}: active Markdown filename must be lowercase kebab-case")
            if str(path.resolve()) not in listed:
                errors.append(f"{path.relative_to(ROOT)}: active document is missing from metadata/documents.yml")

    today = date.today()
    for key, meta in vendor_meta.items():
        for field in ("display_name", "last_verified", "review_cycle_days", "tested_versions", "latest_vendor_version_checked", "official_sources"):
            if field not in meta:
                errors.append(f"vendors.yml:{key}: missing {field}")
        if not meta.get("official_sources"):
            errors.append(f"vendors.yml:{key}: official_sources must not be empty")
        try:
            checked = _date(meta.get("last_verified"))
            cycle = int(meta.get("review_cycle_days", 90))
            if checked + timedelta(days=cycle) < today:
                warnings.append(f"vendors.yml:{key}: vendor review is stale ({checked.isoformat()}, cycle {cycle} days)")
        except (TypeError, ValueError):
            errors.append(f"vendors.yml:{key}: invalid last_verified/review_cycle_days")

    for message in warnings:
        print(f"WARNING: {message}")
    for message in errors:
        print(f"ERROR: {message}", file=sys.stderr)

    if errors:
        print(f"Documentation validation failed with {len(errors)} error(s).", file=sys.stderr)
        return 1
    print(f"Documentation validation passed ({len(docs_meta)} active documents, {len(vendor_meta)} vendor records).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
