"""PAN-OS security-profile definition inventory.

Profile definitions are intentionally source-only.  Profile-group and direct
Security-rule consumers can resolve these records for audit without pretending
that PAN-specific threat semantics are portable.
"""

from __future__ import annotations

from typing import Iterable
import xml.etree.ElementTree as ET

from .extraction import add_source_section, record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope, PANSourceObject
from .xml_utils import structured_xml_capture, text_or_none
from fwmigrate.extraction.models import ExtractionStatus


PROFILE_FAMILIES = (
    "virus", "antivirus", "spyware", "anti-spyware", "vulnerability",
    "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering",
    "wildfire", "sctp", "gtp", "voip",
)


def _profile_entries(search_root: ET.Element) -> Iterable[tuple[str, ET.Element, str]]:
    for container_name in ("profiles", "security-profiles"):
        container = search_root.find(f"./{container_name}")
        if container is None:
            continue
        for family_node in container:
            if family_node.tag not in PROFILE_FAMILIES:
                continue
            for entry in family_node.findall("./entry"):
                yield family_node.tag, entry, f"{container_name}/{family_node.tag}"


def extract_security_profiles(scope: PANScope, search_root: ET.Element, extraction, resolver) -> None:
    containers = [
        container for container_name in ("profiles", "security-profiles")
        for container in ([search_root.find(f"./{container_name}")] if search_root.find(f"./{container_name}") is not None else [])
    ]
    entries = list(_profile_entries(search_root))
    unknown_families = [
        (container, family)
        for container in containers
        for family in container
        if family.tag not in PROFILE_FAMILIES
    ]
    if not entries and not unknown_families and containers:
        for container in containers:
            record_unsupported(
                extraction, "security_profiles", container.tag, scope, container.tag,
                {"pan_source_entry": structured_xml_capture(container)},
                notes=["PAN-OS security-profile container has no recognized profile entries."],
            )
        add_source_section(
            extraction, "profiles/security-profiles", ExtractionStatus.UNSUPPORTED,
            len(containers), len(containers), 0, "extract_security_profiles",
            source_context=f"{scope.kind}:{scope.name}",
        )
        return
    if not entries and not unknown_families:
        return
    parsed = 0
    for family, entry, prefix in entries:
        name = entry.get("name")
        path = f"{prefix}/entry[@name='{name}']" if name else f"{prefix}/entry"
        attributes = {
            "pan_profile_type": family,
            "pan_description": text_or_none(entry, "./description"),
            "pan_profile_settings": structured_xml_capture(entry),
            "pan_source_entry": structured_xml_capture(entry),
        }
        attributes = {key: value for key, value in attributes.items() if value is not None}
        if not name:
            record_parse_error(
                extraction, "security_profiles", path, scope, None, attributes,
                notes=["PAN-OS security profile is missing its required name."],
            )
            continue
        source_object = PANSourceObject(
            name=name, kind="security-profile", domain="security-profile",
            source_path=path, scope=scope, attributes=attributes,
        )
        resolver.register_object(source_object, f"security-profile:{family}")
        # This aggregate namespace is useful for audit callers, while
        # family-specific lookup remains preferred when names collide.
        resolver.register_object(source_object, "security-profile-reference")
        record_extract_only(
            extraction, "security_profiles", path, scope, name, attributes,
            notes=[f"PAN-OS {family} security profile retained as structured source-only inventory."],
            requires_manual_review=True,
        )
        parsed += 1
    for container, family in unknown_families:
        path = f"{container.tag}/{family.tag}"
        entries_for_family = list(family.findall("./entry")) or [family]
        for index, entry in enumerate(entries_for_family):
            name = entry.get("name") or family.tag
            record_unsupported(
                extraction, "security_profiles", f"{path}/entry[{index}]", scope, name,
                {"pan_profile_family": family.tag,
                 "pan_source_entry": structured_xml_capture(entry)},
                notes=[f"PAN-OS security profile family {family.tag} is not recognized by the extractor."],
            )
    add_source_section(
        extraction, "profiles/security-profiles", ExtractionStatus.EXTRACT_ONLY,
        len(entries) + sum(len(family.findall("./entry")) or 1 for _, family in unknown_families),
        parsed, 0, "extract_security_profiles",
        source_context=f"{scope.kind}:{scope.name}",
    )
