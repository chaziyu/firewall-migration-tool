from dataclasses import dataclass
import re
from typing import List, Optional


MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


@dataclass(frozen=True)
class ParsedMACEntry:
    start: str
    end: Optional[str] = None


@dataclass(frozen=True)
class MACParseResult:
    entries: List[ParsedMACEntry]
    invalid_tokens: List[str]

    @property
    def valid(self) -> bool:
        return not self.invalid_tokens and bool(self.entries)


def normalize_mac_address(value: str) -> Optional[str]:
    if not MAC_RE.fullmatch(value):
        return None
    return value.upper()


def parse_fortigate_macaddr(value: str) -> MACParseResult:
    entries = []
    invalid_tokens = []
    for token in value.split():
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            start = normalize_mac_address(start_raw)
            end = normalize_mac_address(end_raw)
            if start is None or end is None or int(start.replace(":", ""), 16) > int(end.replace(":", ""), 16):
                invalid_tokens.append(token)
            else:
                entries.append(ParsedMACEntry(start, end))
        else:
            start = normalize_mac_address(token)
            if start is None:
                invalid_tokens.append(token)
            else:
                entries.append(ParsedMACEntry(start))
    return MACParseResult(entries, invalid_tokens)
