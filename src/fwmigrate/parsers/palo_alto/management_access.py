"""Extract PAN-OS management-plane access as source-only evidence.

PAN-OS does not have a FortiGate-style Local-In Policy rulebase.  Management
access is configured through interface management profiles and device/system
controls, so this module must not convert it into transit Security Policy,
route, NAT, or canonical firewall-service semantics.
"""

from __future__ import annotations

from typing import Optional
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error
from .source_model import PANScope
from .xml_utils import collect_unknown_children, structured_xml_capture


MANAGEMENT_ACCESS_DOMAIN = "management_access"
INTERFACE_MANAGEMENT_PROFILE = "interface-management-profile"

PROFILE_BASE_PATH = "network/profiles/interface-management-profile"
SYSTEM_PATHS = {
    "permitted-ip": ("system-management-access", "deviceconfig/system/permitted-ip"),
    "service": ("system-management-access", "deviceconfig/system/service"),
    "ip-address": ("management-interface-access", "deviceconfig/system/ip-address"),
    "netmask": ("management-interface-access", "deviceconfig/system/netmask"),
    "default-gateway": ("management-interface-access", "deviceconfig/system/default-gateway"),
    "type": ("management-interface-access", "deviceconfig/system/type"),
}


class PANManagementAccessExtractor:
    """Own PAN-OS management-access discovery and source accounting."""

    @staticmethod
    def _evidence(scope: PANScope, kind: str, path: str, entry: ET.Element) -> dict:
        unknown = collect_unknown_children(entry, [])
        evidence = {
            "pan_management_access_kind": kind,
            "pan_scope_kind": scope.kind,
            "pan_scope_name": scope.name,
            "pan_source_path": path,
            "pan_source_entry": structured_xml_capture(entry),
        }
        if scope.device_serial:
            evidence["pan_device_serial"] = scope.device_serial
        if unknown:
            evidence["pan_unknown_fields"] = unknown
        return evidence

    @staticmethod
    def _record(
        extraction: ExtractionResult,
        scope: PANScope,
        kind: str,
        path: str,
        entry: ET.Element,
        name: Optional[str],
    ) -> None:
        record_extract_only(
            extraction,
            MANAGEMENT_ACCESS_DOMAIN,
            path,
            scope,
            name,
            PANManagementAccessExtractor._evidence(scope, kind, path, entry),
            notes=[
                "PAN-OS management-plane access is retained as source-only evidence; "
                "effective access correlation is deferred."
            ],
            requires_manual_review=True,
        )

    @staticmethod
    def _profile_root(search_root: ET.Element) -> Optional[ET.Element]:
        direct = search_root.find("./network/profiles/interface-management-profile")
        if direct is not None:
            return direct
        return search_root.find("./profiles/interface-management-profile")

    @staticmethod
    def _system_root(search_root: ET.Element) -> Optional[ET.Element]:
        return search_root.find("./deviceconfig/system")

    @classmethod
    def _extract_profiles(
        cls, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult
    ) -> None:
        profile_root = cls._profile_root(search_root)
        if profile_root is None:
            return

        entries = list(profile_root.findall("./entry"))
        for entry in entries:
            name = entry.get("name")
            path = (
                f"{PROFILE_BASE_PATH}/entry[@name='{name}']"
                if name
                else f"{PROFILE_BASE_PATH}/entry"
            )
            if not name:
                record_parse_error(
                    extraction,
                    MANAGEMENT_ACCESS_DOMAIN,
                    path,
                    scope,
                    None,
                    cls._evidence(scope, INTERFACE_MANAGEMENT_PROFILE, path, entry),
                    notes=["PAN-OS interface management profile is missing its required name."],
                )
                continue
            cls._record(extraction, scope, INTERFACE_MANAGEMENT_PROFILE, path, entry, name)

        add_source_section(
            extraction,
            PROFILE_BASE_PATH,
            ExtractionStatus.PARSE_ERROR if any(not entry.get("name") for entry in entries)
            else ExtractionStatus.EXTRACT_ONLY,
            len(entries),
            sum(bool(entry.get("name")) for entry in entries),
            0,
            "PANManagementAccessExtractor._extract_profiles",
            source_context=f"{scope.kind}:{scope.name}",
        )

    @classmethod
    def _extract_system(
        cls, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult
    ) -> None:
        system_root = cls._system_root(search_root)
        if system_root is None:
            return

        for child in system_root:
            if child.tag not in SYSTEM_PATHS:
                continue
            kind, path = SYSTEM_PATHS[child.tag]
            cls._record(extraction, scope, kind, path, child, child.get("name"))
            add_source_section(
                extraction,
                path,
                ExtractionStatus.EXTRACT_ONLY,
                1,
                1,
                0,
                "PANManagementAccessExtractor._extract_system",
                source_context=f"{scope.kind}:{scope.name}",
            )

    @classmethod
    def extract(
        cls, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult
    ) -> None:
        """Discover confirmed management-access branches below one source scope."""
        cls._extract_profiles(scope, search_root, extraction)
        cls._extract_system(scope, search_root, extraction)


extract_management_access = PANManagementAccessExtractor.extract
