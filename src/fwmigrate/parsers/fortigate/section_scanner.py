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
    stack: list[SourceSectionResult] = []

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
            parent_path = stack[-1].path if stack else ""
            section = SourceSectionResult(
                path=f"{parent_path} {section_name}".strip(),
                line_start=line_number,
                object_count_source=0,
                status=ExtractionStatus.UNSUPPORTED,
            )
            sections.append(section)
            stack.append(section)
        elif command == "edit" and stack:
            stack[-1].object_count_source = (
                stack[-1].object_count_source or 0
            ) + 1
        elif command == "end" and stack:
            stack.pop().line_end = line_number

    final_line = len(lines) or None
    while stack:
        section = stack.pop()
        section.line_end = final_line
        section.notes.append(
            "Section did not contain a matching end command; range ends at EOF."
        )

    return sections

