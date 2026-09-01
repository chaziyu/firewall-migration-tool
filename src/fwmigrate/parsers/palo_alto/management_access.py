"""Extract PAN-OS management-plane access as source-only evidence.

PAN-OS does not have a FortiGate-style Local-In Policy rulebase.  Management
access is configured through interface management profiles and device/system
controls, so this module must not convert it into transit Security Policy,
route, NAT, or canonical firewall-service semantics.
"""

from __future__ import annotations

import ipaddress
from typing import Optional
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error
from .source_model import PANScope
from .xml_utils import collect_unknown_children, structured_xml_capture


MANAGEMENT_ACCESS_DOMAIN = "management_access"
INTERFACE_MANAGEMENT_PROFILE = "interface-management-profile"

INTERFACE_MANAGEMENT_SERVICE_FIELDS = (
    "http",
    "https",
    "ping",
    "response-pages",
    "userid-service",
    "userid-syslog-listener-ssl",
    "userid-syslog-listener-udp",
    "ssh",
    "telnet",
    "snmp",
    "http-ocsp",
)

# Profiles define firewall-hosted services and source restrictions; exposure
# depends on interface assignment, which is intentionally deferred.

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
    def _strict_yes_no(node: Optional[ET.Element]) -> tuple[object, bool, str | None]:
        if node is None:
            return None, False, None
        source_value = (node.text or "").strip()
        normalized = source_value.lower()
        if normalized == "yes":
            return True, True, normalized
        if normalized == "no":
            return False, True, normalized
        return source_value, True, source_value

    @staticmethod
    def _valid_permitted_ip(value: str) -> bool:
        candidate = value.strip()
        try:
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return True

    @classmethod
    def _profile_evidence(
        cls, scope: PANScope, path: str, entry: ET.Element, name: Optional[str]
    ) -> tuple[dict, list[str]]:
        source = structured_xml_capture(entry)
        evidence = {
            "pan_management_access_kind": INTERFACE_MANAGEMENT_PROFILE,
            "pan_management_profile_name": name,
            "pan_management_profile_source": source,
            "pan_source_entry": source,
            "pan_scope_kind": scope.kind,
            "pan_scope_name": scope.name,
            "pan_source_path": path,
            "pan_management_profile_services": {},
            "pan_management_profile_service_presence": {},
            "pan_management_profile_permitted_ips": [],
            "pan_management_profile_permitted_ip_explicit": False,
        }
        if scope.device_serial:
            evidence["pan_device_serial"] = scope.device_serial

        issues: list[str] = []
        invalid_services: list[str] = []
        for field in INTERFACE_MANAGEMENT_SERVICE_FIELDS:
            node = entry.find(f"./{field}")
            value, present, source_value = cls._strict_yes_no(node)
            if not present:
                continue
            evidence["pan_management_profile_services"][field] = value
            evidence["pan_management_profile_service_presence"][field] = True
            if source_value not in {"yes", "no"}:
                invalid_services.append(field)
        if invalid_services:
            evidence["pan_management_profile_invalid_services"] = invalid_services
            issues.append("malformed service values: " + ", ".join(invalid_services))

        known_fields = [*INTERFACE_MANAGEMENT_SERVICE_FIELDS, "permitted-ip"]
        unknown_fields = collect_unknown_children(entry, known_fields)
        if unknown_fields:
            evidence["pan_management_profile_unknown_fields"] = unknown_fields
            # Keep the Phase 8 generic key for existing inventory consumers.
            evidence["pan_unknown_fields"] = unknown_fields

        permitted_ip = entry.find("./permitted-ip")
        if permitted_ip is not None:
            evidence["pan_management_profile_permitted_ip_explicit"] = True
            evidence["pan_management_profile_permitted_ip_source"] = structured_xml_capture(permitted_ip)
            invalid_ips: list[str] = []
            missing_names: list[int] = []
            unknown_permitted: dict = {}
            for index, ip_entry in enumerate(permitted_ip.findall("./entry")):
                value = ip_entry.get("name")
                if not value:
                    missing_names.append(index)
                    continue
                evidence["pan_management_profile_permitted_ips"].append(value)
                if not cls._valid_permitted_ip(value):
                    invalid_ips.append(value)
                unknown = collect_unknown_children(ip_entry, [])
                if unknown:
                    unknown_permitted[value] = unknown
            container_unknown = collect_unknown_children(permitted_ip, ["entry"])
            if container_unknown:
                unknown_permitted["permitted-ip"] = container_unknown
            if unknown_permitted:
                evidence["pan_management_profile_unknown_permitted_ip_fields"] = unknown_permitted
            if invalid_ips:
                evidence["pan_management_profile_invalid_permitted_ips"] = invalid_ips
                issues.append("malformed permitted IP values")
            if missing_names:
                evidence["pan_management_profile_missing_permitted_ip_names"] = missing_names
                issues.append("permitted-ip entries missing required names")

        return evidence, issues

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
        names = [entry.get("name") for entry in entries]
        duplicate_names = {
            name for name in names if name and names.count(name) > 1
        }
        for entry in entries:
            source_name = entry.get("name")
            name = source_name if source_name and source_name.strip() else None
            path = (
                f"{PROFILE_BASE_PATH}/entry[@name='{source_name}']"
                if name
                else f"{PROFILE_BASE_PATH}/entry"
            )
            evidence, issues = cls._profile_evidence(scope, path, entry, name)
            if not name:
                issues.insert(0, "missing required profile name")
            if source_name in duplicate_names:
                issues.append("duplicate profile name in the same scope")
            unknown_fields_present = bool(
                evidence.get("pan_management_profile_unknown_fields")
                or evidence.get("pan_management_profile_unknown_permitted_ip_fields")
            )

            if issues:
                record_parse_error(
                    extraction, MANAGEMENT_ACCESS_DOMAIN, path, scope, name,
                    evidence,
                    notes=[
                        "PAN-OS Interface Management Profile retained as structured source-only evidence; "
                        + "; ".join(issues) + "."
                    ],
                )
            else:
                note = (
                    "Unrepresented management-profile fields were retained for review."
                    if unknown_fields_present else
                    "PAN-OS Interface Management Profile retained as structured source-only "
                    "management-access evidence; effective access depends on interface assignment."
                )
                record_extract_only(
                    extraction, MANAGEMENT_ACCESS_DOMAIN, path, scope, name,
                    evidence,
                    notes=[note],
                    requires_manual_review=True,
                )

        source_context = (
            f"{scope.kind}:{scope.name}:device:{scope.device_serial}"
            if scope.device_serial else f"{scope.kind}:{scope.name}"
        )
        add_source_section(
            extraction,
            PROFILE_BASE_PATH,
            ExtractionStatus.PARSE_ERROR if any(
                item.domain == MANAGEMENT_ACCESS_DOMAIN
                and item.source_path.startswith(PROFILE_BASE_PATH)
                and item.status == ExtractionStatus.PARSE_ERROR
                and item.source_context == source_context
                for item in extraction.inventory_items
            )
            else ExtractionStatus.EXTRACT_ONLY,
            len(entries),
            sum(bool(entry.get("name") and entry.get("name").strip()) for entry in entries),
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
