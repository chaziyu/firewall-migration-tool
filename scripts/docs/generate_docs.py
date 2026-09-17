from __future__ import annotations

import argparse
from pathlib import Path

from fwmigrate.builtin_plugins import register_builtin_plugins

register_builtin_plugins()
from fwmigrate.core.registry import PluginRegistry

ROOT = Path(__file__).resolve().parents[2]
GENERATED_DIR = ROOT / "documentation" / "generated"


def _join(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values)


def render_capabilities() -> str:
    sources = sorted(PluginRegistry.list_source_vendors(), key=lambda item: item["vendor_id"])
    targets = sorted(PluginRegistry.list_target_vendors(), key=lambda item: item["vendor_id"])
    lines = [
        "# Registered Vendor Capabilities",
        "",
        "<!-- GENERATED FILE. DO NOT EDIT DIRECTLY. -->",
        "",
        "This file is generated from the runtime plugin registry. It reports registration, not feature-level semantic parity.",
        "",
        "## Source parsers",
        "",
        "| Source ID | Display name | Accepted extensions | Aliases | Status |",
        "|---|---|---|---|---|",
    ]
    for item in sources:
        lines.append(
            f"| `{item['vendor_id']}` | {item['display_name']} | "
            f"{_join(list(item['file_extensions']))} | {_join(list(item['aliases'])) or '—'} | "
            f"{'experimental' if item['experimental'] else 'stable'} |"
        )
    lines += [
        "",
        "## Target generators",
        "",
        "| Target ID | Display name | Registered formats | Aliases | Status |",
        "|---|---|---|---|---|",
    ]
    for item in targets:
        lines.append(
            f"| `{item['vendor_id']}` | {item['display_name']} | "
            f"{_join(list(item['supported_formats']))} | {_join(list(item['aliases'])) or '—'} | "
            f"{'experimental' if item['experimental'] else 'stable'} |"
        )
    lines += [
        "",
        "> A registered source and a registered target do not imply lossless feature parity. Review the vendor support matrix, migration warnings, and exported inventory before deployment.",
        "",
    ]
    return "\n".join(lines)


def _write_or_check(path: Path, content: str, check: bool) -> bool:
    if check:
        actual = path.read_text(encoding="utf-8") if path.exists() else None
        if actual != content:
            print(f"OUT OF DATE: {path.relative_to(ROOT)}")
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"WROTE: {path.relative_to(ROOT)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate code-derived documentation.")
    parser.add_argument("--check", action="store_true", help="Fail if committed generated files are stale.")
    args = parser.parse_args()

    outputs = {
        GENERATED_DIR / "capabilities.md": render_capabilities(),
    }
    results = [_write_or_check(path, content, args.check) for path, content in outputs.items()]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
