"""Structural FortiGate ``config`` section discovery."""

from __future__ import annotations

import shlex

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


def _command_parts(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def scan_fortigate_sections(text: str) -> list[SourceSectionResult]:
    """Inventory structural config blocks without interpreting their settings."""
    sections: list[SourceSectionResult] = []
    stack: list[dict[str, object]] = []
    current_vdom: str | None = None

    lines = text.splitlines()
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = _command_parts(line)
        if not parts:
            continue

        command = parts[0].lower()
        if command == "config" and len(parts) > 1:
            section_name = " ".join(parts[1:])
            parent_path = ""
            for entry in reversed(stack):
                if not entry["is_vdom"]:
                    parent_path = str(entry["section"].path)
                    break
            section = SourceSectionResult(
                path=f"{parent_path} {section_name}".strip(),
                source_context=current_vdom,
                line_start=line_number,
                object_count_source=0,
                status=ExtractionStatus.UNSUPPORTED,
            )
            sections.append(section)
            stack.append({
                "section": section,
                "is_vdom": section_name.lower() == "vdom" and not parent_path,
            })
        elif command == "edit" and stack:
            top = stack[-1]
            section = top["section"]
            section.object_count_source = (
                section.object_count_source or 0
            ) + 1
            if top["is_vdom"]:
                current_vdom = parts[1] if len(parts) > 1 else None
        elif command == "next" and stack and stack[-1]["is_vdom"]:
            current_vdom = None
        elif command == "end" and stack:
            entry = stack.pop()
            entry["section"].line_end = line_number
            if entry["is_vdom"]:
                current_vdom = None

    final_line = len(lines) or None
    while stack:
        section = stack.pop()["section"]
        section.line_end = final_line
        section.notes.append(
            "Section did not contain a matching end command; range ends at EOF."
        )

    return sections

