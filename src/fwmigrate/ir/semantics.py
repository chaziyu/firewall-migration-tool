"""Vendor-neutral canonical IR semantic classifications and safety predicates."""

from __future__ import annotations

from enum import Enum
from typing import Optional, Set, TYPE_CHECKING

from fwmigrate.core.constants import IR_KEYWORD_ANY

if TYPE_CHECKING:
    from fwmigrate.ir.core import IRConfig, IRPolicy, IRZone


class AddressUniversalFamily(str, Enum):
    """Semantic classification for universal / wildcard address references."""
    ANY = "any"
    IPV4 = "any-ipv4"
    IPV6 = "any-ipv6"


def classify_universal_address_reference(value: str) -> Optional[AddressUniversalFamily]:
    """
    Classify a canonical address reference into its universal address family, or None if specific.

    Recognizes:
    - ANY: 'any', 'all', and IR_KEYWORD_ANY ('<IR_ANY>')
    - IPV4: 'any-ipv4', 'any4'
    - IPV6: 'any-ipv6', 'any6'
    """
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized == IR_KEYWORD_ANY.lower() or normalized in {"any", "all"}:
        return AddressUniversalFamily.ANY
    if normalized in {"any-ipv4", "any4"}:
        return AddressUniversalFamily.IPV4
    if normalized in {"any-ipv6", "any6"}:
        return AddressUniversalFamily.IPV6
    return None


def is_zone_safe_for_target_generation(zone: IRZone) -> bool:
    """Check if an IRZone is normalized and safe for target configuration generation."""
    return (
        not getattr(zone, "disabled", False)
        and not getattr(zone, "requires_manual_review", False)
        and getattr(zone, "migration_status", "NORMALIZED") == "NORMALIZED"
    )


def unsafe_zone_names(ir: IRConfig) -> Set[str]:
    """Return set of zone names in IRConfig that are unsafe for target generation."""
    return {zone.name for zone in ir.zones if not is_zone_safe_for_target_generation(zone)}


def policy_references_unsafe_zone(policy: IRPolicy, unsafe_zones: Set[str]) -> bool:
    """Check if an IRPolicy references any unsafe zone in from_zone or to_zone."""
    if not unsafe_zones:
        return False
    from_zones = set(getattr(policy, "from_zone", []) or [])
    to_zones = set(getattr(policy, "to_zone", []) or [])
    return bool(from_zones.intersection(unsafe_zones) or to_zones.intersection(unsafe_zones))
