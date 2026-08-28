"""Check Point extraction coverage accounting and section status classification."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from fwmigrate.parsers.checkpoint.loader import canonicalize_command


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
