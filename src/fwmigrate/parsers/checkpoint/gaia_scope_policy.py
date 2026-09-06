"""Canonical-boundary policy for VS-scoped Gaia records.

The current canonical DNS/NTP models are root-scoped. VS-specific values must
therefore stay explicit source evidence instead of being merged into those
root-level scalars. Interfaces retain their VS identity but are review-required
until target generators understand scoped interface identities.
"""

from __future__ import annotations

from typing import Optional

from fwmigrate.parsers.checkpoint.gaia_scoped import GaiaParseResult
from fwmigrate.parsers.checkpoint.gaia_scoped import parse_gaia_configuration as _parse_scoped


_VS_SOURCE_ONLY_TYPES = {
    "gaia-dns": "gaia-dns-vs",
    "gaia-domain-name": "gaia-domain-name-vs",
    "gaia-ntp": "gaia-ntp-vs",
}


def parse_gaia_configuration(
    gaia_text: str,
    *,
    domain: Optional[str] = None,
    gateway: Optional[str] = None,
    source_response: Optional[str] = None,
    cluster_member: Optional[str] = None,
) -> GaiaParseResult:
    result = _parse_scoped(
        gaia_text,
        domain=domain,
        gateway=gateway,
        source_response=source_response,
        cluster_member=cluster_member,
    )
    metadata, interfaces, zones, routes, inventory, unsupported = result

    for interface in interfaces:
        vsid = interface.source_attributes.get("virtual_system_id")
        if vsid is None:
            continue
        interface.requires_manual_review = True
        interface.migration_status = "PARTIALLY_NORMALIZED"
        reason = "vsx-scoped-interface-requires-target-scope"
        if reason not in interface.review_reasons:
            interface.review_reasons.append(reason)

    for item in inventory:
        vsid = item.source_attributes.get("virtual_system_id")
        if vsid is None:
            continue
        replacement = _VS_SOURCE_ONLY_TYPES.get(item.source_type or "")
        if replacement:
            item.source_type = replacement
            item.requires_manual_review = True
            if item.status.value == "NORMALIZED":
                # The command itself parsed exactly, but current root-level IR
                # cannot represent its VS-specific scope without semantic loss.
                from fwmigrate.extraction.models import ExtractionStatus
                item.status = ExtractionStatus.PARTIALLY_NORMALIZED
            note = "VS-specific value withheld from root-level canonical system settings"
            if note not in item.notes:
                item.notes.append(note)

    return metadata, interfaces, zones, routes, inventory, unsupported
