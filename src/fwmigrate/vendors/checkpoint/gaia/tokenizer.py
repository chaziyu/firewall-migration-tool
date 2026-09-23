from __future__ import annotations

import shlex


def tokenize_gaia(text: str) -> list[list[str]]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            lines.append(shlex.split(line))
        except ValueError:
            lines.append(line.split())
    return lines
