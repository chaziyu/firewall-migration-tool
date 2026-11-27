"""Pure IPv4/CIDR/range matching and weak-crypto token helpers for source reporting."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Iterable, Literal

QueryMode = Literal["ip", "cidr", "range", "name"]

_RANGE_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*[-–]\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$")
_SPACE_MASK_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

_WEAK_CIPHER_TOKENS = frozenset({"des", "3des", "md5", "sha1", "sha"})
_WEAK_DH_TOKENS = frozenset({"1", "2", "5", "dh1", "dh2", "dh5", "group1", "group2", "group5"})


@dataclass(frozen=True, slots=True)
class ParsedQuery:
    raw: str
    mode: QueryMode
    network: ipaddress.IPv4Network | None
    start_int: int | None
    end_int: int | None
    needle_lower: str


def parse_ipv4_range(text: str | None) -> tuple[int, int] | None:
    """Parse an IPv4 address, CIDR, space-netmask, or dash-range into inclusive integer bounds."""
    if not text or not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None

    range_match = _RANGE_RE.match(stripped)
    if range_match:
        try:
            start = int(ipaddress.IPv4Address(range_match.group(1)))
            end = int(ipaddress.IPv4Address(range_match.group(2)))
        except ipaddress.AddressValueError:
            return None
        return (start, end) if start <= end else (end, start)

    mask_match = _SPACE_MASK_RE.match(stripped)
    if mask_match:
        try:
            net = ipaddress.IPv4Network(f"{mask_match.group(1)}/{mask_match.group(2)}", strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return None
        return int(net.network_address), int(net.broadcast_address)

    if "/" in stripped:
        try:
            net = ipaddress.IPv4Network(stripped, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return None
        return int(net.network_address), int(net.broadcast_address)

    try:
        addr = ipaddress.IPv4Address(stripped)
    except ipaddress.AddressValueError:
        return None
    val = int(addr)
    return val, val


def parse_where_used_query(raw: str) -> ParsedQuery:
    """Parse a user where-used query as IPv4 host, CIDR, range, or object name."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Search query is required")
    cleaned = raw.strip()

    range_match = _RANGE_RE.match(cleaned)
    if range_match:
        bounds = parse_ipv4_range(cleaned)
        if bounds is not None:
            return ParsedQuery(
                raw=cleaned,
                mode="range",
                network=None,
                start_int=bounds[0],
                end_int=bounds[1],
                needle_lower=cleaned.lower(),
            )

    if "/" in cleaned:
        try:
            net = ipaddress.IPv4Network(cleaned, strict=False)
            return ParsedQuery(
                raw=cleaned,
                mode="cidr",
                network=net,
                start_int=int(net.network_address),
                end_int=int(net.broadcast_address),
                needle_lower=cleaned.lower(),
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            pass

    space_match = _SPACE_MASK_RE.match(cleaned)
    if space_match:
        bounds = parse_ipv4_range(cleaned)
        if bounds is not None:
            net = ipaddress.IPv4Network(f"{space_match.group(1)}/{space_match.group(2)}", strict=False)
            return ParsedQuery(
                raw=cleaned,
                mode="cidr",
                network=net,
                start_int=bounds[0],
                end_int=bounds[1],
                needle_lower=cleaned.lower(),
            )

    try:
        addr = ipaddress.IPv4Address(cleaned)
        net = ipaddress.IPv4Network(f"{addr}/32")
        val = int(addr)
        return ParsedQuery(
            raw=cleaned,
            mode="ip",
            network=net,
            start_int=val,
            end_int=val,
            needle_lower=cleaned.lower(),
        )
    except ipaddress.AddressValueError:
        pass

    return ParsedQuery(
        raw=cleaned,
        mode="name",
        network=None,
        start_int=None,
        end_int=None,
        needle_lower=cleaned.lower(),
    )


def _describe_overlap(q_start: int, q_end: int, c_start: int, c_end: int) -> str:
    if q_start == c_start and q_end == c_end:
        return "exact IP/subnet match"
    if q_start >= c_start and q_end <= c_end:
        return "contained in subnet/range"
    if c_start >= q_start and c_end <= q_end:
        return "contains target IP/subnet"
    return "overlaps IP range"


def query_matches_ip_text(query: ParsedQuery, text: str | None) -> str | None:
    """Return a human-readable match reason if text matches the parsed query."""
    if not text or not isinstance(text, str):
        return None
    if query.mode == "name":
        return "text match" if query.needle_lower in text.lower() else None
    if query.start_int is None or query.end_int is None:
        return None
    bounds = parse_ipv4_range(text)
    if bounds is None:
        return None
    c_start, c_end = bounds
    if query.start_int <= c_end and c_start <= query.end_int:
        return _describe_overlap(query.start_int, query.end_int, c_start, c_end)
    return None


def query_matches_ip_bounds(query: ParsedQuery, start_ip: str | None, end_ip: str | None) -> str | None:
    """Check whether an explicit IPv4 start/end bound pair matches the query."""
    if not start_ip and not end_ip:
        return None
    if start_ip and end_ip:
        return query_matches_ip_text(query, f"{start_ip.strip()}-{end_ip.strip()}")
    return query_matches_ip_text(query, start_ip or end_ip)


def query_matches_name(query: ParsedQuery, name: str | None) -> str | None:
    """Return match reason if an object name matches a name query."""
    if query.mode != "name" or not name:
        return None
    lowered = name.lower()
    if lowered == query.needle_lower:
        return "exact name match"
    if query.needle_lower in lowered:
        return "name contains query"
    return None


def weak_crypto_findings(
    algorithms: Iterable[str | None],
    dh_groups: Iterable[str | int | None] = (),
) -> list[str]:
    """Identify weak ciphers, hashes, or DH groups using exact token boundaries."""
    weak: list[str] = []
    seen: set[str] = set()

    for entry in algorithms:
        if not entry:
            continue
        raw = str(entry).strip()
        lowered = raw.lower()
        tokens = [tok for tok in _TOKEN_SPLIT_RE.split(lowered) if tok]
        if "sha1" in tokens or "sha-1" in lowered or ("sha" in tokens and "1" in tokens):
            label = "SHA-1"
            if label not in seen:
                seen.add(label)
                weak.append(label)
        for tok in tokens:
            if tok in _WEAK_CIPHER_TOKENS and tok != "sha":
                label = tok.upper()
                if label not in seen:
                    seen.add(label)
                    weak.append(label)

    for group in dh_groups:
        if group is None:
            continue
        raw = str(group).strip().lower()
        if not raw:
            continue
        for tok in [t for t in _TOKEN_SPLIT_RE.split(raw) if t]:
            if tok in _WEAK_DH_TOKENS:
                num = tok.lstrip("dhgroup")
                label = f"DH group {num}" if num in {"1", "2", "5"} else tok.upper()
                if label not in seen:
                    seen.add(label)
                    weak.append(label)

    return weak
