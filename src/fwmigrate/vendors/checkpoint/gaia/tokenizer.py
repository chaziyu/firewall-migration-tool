from __future__ import annotations

import shlex
from dataclasses import dataclass
from enum import Enum


class GaiaTokenType(str, Enum):
    SET = "set"
    ADD = "add"
    SHOW = "show"
    CREATE = "create"
    DELETE = "delete"
    STRING = "string"
    COMMENT = "comment"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GaiaToken:
    type: GaiaTokenType
    value: str
    line_number: int


def tokenize_gaia(text: str) -> list[list[GaiaToken]]:
    result: list[list[GaiaToken]] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            result.append([GaiaToken(GaiaTokenType.COMMENT, stripped[1:].lstrip(), line_number)])
            continue
        try:
            values = shlex.split(raw, comments=True, posix=True)
        except ValueError as exc:
            result.append([GaiaToken(GaiaTokenType.UNKNOWN, f"malformed syntax: {exc}: {raw}", line_number)])
            continue
        if not values:
            continue
        result.append([
            GaiaToken({"set": GaiaTokenType.SET, "add": GaiaTokenType.ADD,
                       "show": GaiaTokenType.SHOW, "create": GaiaTokenType.CREATE,
                       "delete": GaiaTokenType.DELETE}.get(value.lower(),
                       GaiaTokenType.STRING if index else GaiaTokenType.UNKNOWN),
                       value, line_number)
            for index, value in enumerate(values)
        ])
    return result
