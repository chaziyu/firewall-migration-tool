from __future__ import annotations

from .section_registry import is_supported_gaia_section
from .tokenizer import tokenize_gaia


def parse_gaia(text: str) -> list[dict[str, object]]:
    result = []
    for tokens in tokenize_gaia(text):
        if len(tokens) < 2 or tokens[0] not in {"set", "add", "show", "create"}:
            result.append({"kind": "unsupported", "tokens": tokens})
            continue
        section = tokens[1]
        if not is_supported_gaia_section(section):
            result.append({"kind": "unsupported", "tokens": tokens})
            continue
        values: dict[str, object] = {"kind": section, "tokens": tokens}
        if len(tokens) > 2:
            values["name"] = tokens[2]
        for index in range(3, len(tokens) - 1, 2):
            values[tokens[index].replace("-", "_")] = tokens[index + 1]
        result.append(values)
    return result
