"""Check Point extraction coverage accounting and section status classification."""

from __future__ import annotations

from typing import Any, Dict, Hashable, List, Optional, Set, Tuple
from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointExportBundle
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase


def authoritative_object_identity(
    obj: Any,
    domain: str,
    source_scope: str,
) -> Tuple[Hashable, ...]:
    """Build a stable per-domain object key with conservative UID-less fallback."""
    if isinstance(obj, dict):
        uid = obj.get("uid")
        if uid:
            return (domain, "uid", str(uid))
        return (
            domain,
            "fallback",
            str(obj.get("type") or "<missing-type>"),
            str(obj.get("name") or "<missing-name>"),
            source_scope,
        )
    return (domain, "malformed", source_scope, repr(obj))


def _dictionary_entries(raw: Any) -> List[Any]:
    if isinstance(raw, dict):
        entries: List[Any] = []
        for key, value in raw.items():
            if isinstance(value, dict) and not value.get("uid") and key:
                value = {**value, "uid": str(key)}
            entries.append(value)
        return entries
    return list(raw) if isinstance(raw, list) else []


def count_authoritative_source_leaves(bundle: CheckPointExportBundle) -> int:
    """Count source constructs that require exactly one authoritative inventory record."""
    count = 0
    authoritative_object_keys: Set[Tuple[Hashable, ...]] = set()
    dictionary_occurrences: List[Tuple[Tuple[Hashable, ...], Any]] = []
    for response in bundle.responses:
        command = canonicalize_command(response.command)
        data = response.data
        domain = response.domain or bundle.domain or "global"
        if response.collection_status == "ERROR":
            count += 1
            continue
        if command == "gaia/show-configuration":
            text = str(data.get("cli_text", ""))
            count += sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))
            continue
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        if isinstance(objects, list):
            for obj in objects:
                identity = authoritative_object_identity(obj, domain, command)
                if identity not in authoritative_object_keys:
                    authoritative_object_keys.add(identity)
                    count += 1
        dictionary = data.get("objects-dictionary")
        for index, obj in enumerate(_dictionary_entries(dictionary)):
            dictionary_scope = f"{command}/objects-dictionary"
            if not isinstance(obj, dict):
                dictionary_scope = f"{dictionary_scope}:{index}"
            identity = authoritative_object_identity(
                obj, domain, dictionary_scope,
            )
            dictionary_occurrences.append((identity, obj))
        rulebase = data.get("rulebase", [])
        if isinstance(rulebase, list):
            count += len(flatten_rulebase(rulebase))
    for identity, _ in dictionary_occurrences:
        if identity not in authoritative_object_keys:
            authoritative_object_keys.add(identity)
            count += 1
    return count


def checkpoint_source_category(command: str) -> str:
    """Return a human-readable inventory category for a canonical Check Point command."""
    cmd = canonicalize_command(command)
    category_map = {
        "show-hosts": "Hosts",
        "show-networks": "Networks",
        "show-address-ranges": "Address Ranges",
        "show-groups": "Address Groups",
        "show-groups-with-exclusion": "Address Groups with Exclusion",
        "show-security-zones": "Security Zones",
        "show-services-tcp": "TCP Services",
        "show-services-udp": "UDP Services",
        "show-services-sctp": "SCTP Services",
        "show-services-icmp": "ICMP Services",
        "show-services-icmp6": "ICMPv6 Services",
        "show-services-other": "Other Services",
        "show-service-groups": "Service Groups",
        "show-access-rulebase": "Access Control Rulebase",
        "show-nat-rulebase": "NAT Rulebase",
        "show-times": "Times",
        "show-time-groups": "Time Groups",
        "show-gateways-and-servers": "Gateways & Servers",
        "show-packages": "Policy Packages",
        "show-objects": "Objects",
        "gaia/show-configuration": "Gaia System Configuration",
    }
    return category_map.get(cmd, f"Check Point {cmd}")


def create_section_result(
    command: str,
    domain: Optional[str] = None,
    package: Optional[str] = None,
    layer: Optional[str] = None,
    gateway: Optional[str] = None,
    source_count: int = 0,
    parsed_count: int = 0,
    normalized_count: int = 0,
    status: ExtractionStatus = ExtractionStatus.NORMALIZED,
    parser_handler: Optional[str] = None,
    notes: Optional[List[str]] = None,
) -> SourceSectionResult:
    """Construct a standardized SourceSectionResult for a Check Point command section."""
    cmd = canonicalize_command(command)
    parts = ["checkpoint", cmd]
    if domain:
        parts.append(domain)
    if cmd == "show-access-rulebase":
        parts.append(package or "<missing-package>")
        parts.append(layer or "<missing-layer>")
    elif cmd == "show-nat-rulebase":
        parts.append(package or "<missing-package>")
    else:
        if package:
            parts.append(package)
        if layer:
            parts.append(layer)
    if gateway:
        parts.append(gateway)

    path = "/".join(parts)

    return SourceSectionResult(
        path=path,
        present=True,
        object_count_source=source_count,
        object_count_parsed=parsed_count,
        object_count_normalized=normalized_count,
        status=status,
        parser_handler=parser_handler or f"checkpoint.{cmd}",
        notes=notes or [],
    )
