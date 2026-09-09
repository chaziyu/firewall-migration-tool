"""Extract PAN-OS management-plane access as source-only evidence.

PAN-OS does not have a FortiGate-style Local-In Policy rulebase.  Management
access is configured through interface management profiles and device/system
controls, so this module must not convert it into transit Security Policy,
route, NAT, or canonical firewall-service semantics.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional
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

SYSTEM_SERVICE_DISABLE_FIELDS = (
    "disable-http",
    "disable-https",
    "disable-telnet",
    "disable-ssh",
    "disable-icmp",
    "disable-snmp",
    "disable-userid-service",
    "disable-userid-syslog-listener-ssl",
    "disable-userid-syslog-listener-udp",
    "disable-http-ocsp",
)

SYSTEM_SERVICE_SEMANTICS = {
    "disable-http": "http",
    "disable-https": "https",
    "disable-telnet": "telnet",
    "disable-ssh": "ssh",
    "disable-icmp": "ping",
    "disable-snmp": "snmp",
    "disable-userid-service": "userid-service",
    "disable-userid-syslog-listener-ssl": "userid-syslog-listener-ssl",
    "disable-userid-syslog-listener-udp": "userid-syslog-listener-udp",
    "disable-http-ocsp": "http-ocsp",
}

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
    "ipv6-address": ("management-interface-access", "deviceconfig/system/ipv6-address"),
    "ipv6-default-gateway": (
        "management-interface-access", "deviceconfig/system/ipv6-default-gateway"
    ),
    "ipv6-enable": ("management-interface-access", "deviceconfig/system/ipv6-enable"),
    "ipv6-type": ("management-interface-access", "deviceconfig/system/ipv6-type"),
    "ipv6-gw-type": ("management-interface-access", "deviceconfig/system/ipv6-gw-type"),
}

SYSTEM_CHOICE_FIELDS = {
    "type": ("pan_system_management_type", ("static", "dhcp-client")),
    "ipv6-type": ("pan_system_management_ipv6_type", ("static", "dynamic")),
    "ipv6-gw-type": (
        "pan_system_management_ipv6_gateway_type", ("static", "dynamic")
    ),
}

SYSTEM_SCALAR_FIELDS = {
    "ip-address": ("pan_system_management_ip_address", "ipv4-address"),
    "netmask": ("pan_system_management_netmask", "ipv4-netmask"),
    "default-gateway": ("pan_system_management_default_gateway", "ipv4-address"),
    "ipv6-address": ("pan_system_management_ipv6_address", "ipv6-address"),
    "ipv6-default-gateway": (
        "pan_system_management_ipv6_default_gateway", "ipv6-address"
    ),
}


class PANManagementAccessExtractor:
    """Own PAN-OS management-access discovery and source accounting."""

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

    @staticmethod
    def _system_base_evidence(
        scope: PANScope, kind: str, path: str, entry: ET.Element
    ) -> dict:
        source = structured_xml_capture(entry)
        evidence = {
            "pan_management_access_kind": kind,
            "pan_scope_kind": scope.kind,
            "pan_scope_name": scope.name,
            "pan_source_path": path,
            "pan_source_entry": source,
        }
        if scope.device_serial:
            evidence["pan_device_serial"] = scope.device_serial
        return evidence

    @staticmethod
    def _valid_ipv4_netmask(value: str) -> bool:
        try:
            ipaddress.IPv4Network(f"0.0.0.0/{value.strip()}")
        except ValueError:
            return False
        return True

    @staticmethod
    def _valid_scalar_ip(value: str, version: int) -> bool:
        try:
            parsed = ipaddress.ip_interface(value.strip()) if "/" in value else ipaddress.ip_address(value.strip())
        except ValueError:
            return False
        return parsed.version == version

    @classmethod
    def _system_service_evidence(
        cls, scope: PANScope, path: str, service: ET.Element
    ) -> tuple[dict, list[str], bool]:
        evidence = cls._system_base_evidence(
            scope, "system-management-access", path, service
        )
        evidence["pan_system_management_service_source"] = structured_xml_capture(service)
        evidence["pan_system_management_service_disable"] = {}
        evidence["pan_system_management_services"] = {}
        evidence["pan_system_management_service_presence"] = {}

        invalid_services: list[str] = []
        for field in SYSTEM_SERVICE_DISABLE_FIELDS:
            value, present, source_value = cls._strict_yes_no(service.find(f"./{field}"))
            if not present:
                continue
            evidence["pan_system_management_service_disable"][field] = value
            evidence["pan_system_management_service_presence"][field] = True
            if source_value in {"yes", "no"}:
                evidence["pan_system_management_services"][SYSTEM_SERVICE_SEMANTICS[field]] = not value
            else:
                invalid_services.append(field)

        unknown = collect_unknown_children(service, list(SYSTEM_SERVICE_DISABLE_FIELDS))
        if unknown:
            evidence["pan_system_management_unknown_service_fields"] = unknown
            evidence["pan_unknown_fields"] = unknown
        if invalid_services:
            evidence["pan_system_management_invalid_services"] = invalid_services
        return evidence, invalid_services, bool(unknown)

    @classmethod
    def _system_permitted_ip_evidence(
        cls, scope: PANScope, path: str, permitted_ip: ET.Element
    ) -> tuple[dict, list[str], bool]:
        evidence = cls._system_base_evidence(
            scope, "system-management-access", path, permitted_ip
        )
        evidence["pan_system_management_permitted_ip_source"] = structured_xml_capture(permitted_ip)
        evidence["pan_system_management_permitted_ip_explicit"] = True
        evidence["pan_system_management_permitted_ips"] = []
        evidence["pan_system_management_permitted_ip_details"] = []

        invalid_ips: list[str] = []
        missing_names: list[int] = []
        unknown_fields: dict = {}
        for index, entry in enumerate(permitted_ip.findall("./entry")):
            value = entry.get("name")
            if value is None or not value.strip():
                missing_names.append(index)
                unknown = collect_unknown_children(entry, ["description"])
                if unknown:
                    unknown_fields[f"entry[{index}]"] = unknown
                continue

            evidence["pan_system_management_permitted_ips"].append(value)
            detail = {"value": value}
            description = entry.find("./description")
            if description is not None:
                detail["description"] = (description.text or "").strip()
            evidence["pan_system_management_permitted_ip_details"].append(detail)
            if not cls._valid_permitted_ip(value):
                invalid_ips.append(value)
            unknown = collect_unknown_children(entry, ["description"])
            if unknown:
                unknown_fields[value] = unknown

        container_unknown = collect_unknown_children(permitted_ip, ["entry"])
        if container_unknown:
            unknown_fields["permitted-ip"] = container_unknown
        if invalid_ips:
            evidence["pan_system_management_invalid_permitted_ips"] = invalid_ips
        if missing_names:
            evidence["pan_system_management_missing_permitted_ip_names"] = missing_names
        if unknown_fields:
            evidence["pan_system_management_unknown_permitted_ip_fields"] = unknown_fields
            evidence["pan_unknown_fields"] = unknown_fields
        issues = []
        if invalid_ips:
            issues.append("malformed permitted IP values")
        if missing_names:
            issues.append("permitted-ip entries missing required names")
        return evidence, issues, bool(unknown_fields)

    @classmethod
    def _system_choice_evidence(
        cls, scope: PANScope, path: str, node: ET.Element, evidence_key: str,
        supported_choices: tuple[str, ...],
    ) -> tuple[dict, list[str], bool]:
        evidence = cls._system_base_evidence(
            scope, "management-interface-access", path, node
        )
        source = structured_xml_capture(node)
        evidence["pan_system_management_source"] = source
        issues: list[str] = []
        children = list(node)
        supported = [child.tag for child in children if child.tag in supported_choices]
        unknown = collect_unknown_children(node, list(supported_choices))
        if len(supported) == 1:
            evidence[evidence_key] = supported[0]
        elif len(supported) == 0 and not unknown:
            issues.append("management choice container is empty")
        elif len(supported) > 1:
            issues.append("management choice container has mutually exclusive choices")
        if unknown:
            evidence["pan_system_management_unknown_choices"] = unknown
            evidence["pan_unknown_fields"] = unknown
        return evidence, issues, bool(unknown)

    @classmethod
    def _system_scalar_evidence(
        cls, scope: PANScope, kind: str, path: str, field: str, node: ET.Element
    ) -> tuple[dict, list[str], bool]:
        evidence = cls._system_base_evidence(scope, kind, path, node)
        key, value_type = SYSTEM_SCALAR_FIELDS[field]
        value = (node.text or "").strip()
        evidence[key] = value
        if value_type == "ipv4-address":
            valid = cls._valid_scalar_ip(value, 4)
        elif value_type == "ipv4-netmask":
            valid = cls._valid_ipv4_netmask(value)
        else:
            valid = cls._valid_scalar_ip(value, 6)
        issues = [] if valid else [f"invalid {field} value"]
        unknown = collect_unknown_children(node, [])
        if unknown:
            evidence["pan_unknown_fields"] = unknown
        return evidence, issues, bool(unknown)

    @classmethod
    def _system_boolean_evidence(
        cls, scope: PANScope, path: str, node: ET.Element
    ) -> tuple[dict, list[str], bool]:
        evidence = cls._system_base_evidence(
            scope, "management-interface-access", path, node
        )
        value, _, source_value = cls._strict_yes_no(node)
        evidence["pan_system_management_ipv6_enabled"] = value
        issues = [] if source_value in {"yes", "no"} else ["invalid ipv6-enable value"]
        unknown = collect_unknown_children(node, [])
        if unknown:
            evidence["pan_unknown_fields"] = unknown
        return evidence, issues, bool(unknown)

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
            if child.tag == "service":
                evidence, issues, manual_review = cls._system_service_evidence(scope, path, child)
            elif child.tag == "permitted-ip":
                evidence, issues, manual_review = cls._system_permitted_ip_evidence(scope, path, child)
            elif child.tag in SYSTEM_CHOICE_FIELDS:
                evidence_key, choices = SYSTEM_CHOICE_FIELDS[child.tag]
                evidence, issues, manual_review = cls._system_choice_evidence(
                    scope, path, child, evidence_key, choices
                )
            elif child.tag == "ipv6-enable":
                evidence, issues, manual_review = cls._system_boolean_evidence(scope, path, child)
            else:
                evidence, issues, manual_review = cls._system_scalar_evidence(
                    scope, kind, path, child.tag, child
                )

            notes = [
                "PAN-OS management-plane access is retained as source-only evidence; "
                "effective access correlation is deferred."
            ]
            if issues:
                record_parse_error(
                    extraction, MANAGEMENT_ACCESS_DOMAIN, path, scope, child.get("name"),
                    evidence, notes=notes + issues,
                )
                status = ExtractionStatus.PARSE_ERROR
                parsed_count = 0
            else:
                if manual_review:
                    notes.append("Unrepresented management fields were retained for review.")
                record_extract_only(
                    extraction, MANAGEMENT_ACCESS_DOMAIN, path, scope, child.get("name"),
                    evidence, notes=notes, requires_manual_review=True,
                )
                status = ExtractionStatus.EXTRACT_ONLY
                parsed_count = 1
            add_source_section(
                extraction,
                path,
                status,
                1,
                parsed_count,
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


class PANManagementAccessCorrelator:
    """Project resolved interface-management profiles onto IR interfaces."""

    @staticmethod
    def _scope_context(scope: PANScope) -> str:
        return (
            f"{scope.kind}:{scope.name}:device:{scope.device_serial}"
            if scope.device_serial else f"{scope.kind}:{scope.name}"
        )

    @staticmethod
    def _review(interface, inventory, reason: str) -> None:
        if reason not in interface.review_reasons:
            interface.review_reasons.append(reason)
        interface.requires_manual_review = True
        if interface.migration_status == "NORMALIZED":
            interface.migration_status = "PARTIALLY_NORMALIZED"
        if inventory is not None:
            if reason not in inventory.notes:
                inventory.notes.append(f"PAN-OS management correlation requires review: {reason}.")
            inventory.requires_manual_review = True
            if (inventory.status != ExtractionStatus.PARSE_ERROR
                    and inventory.status == ExtractionStatus.NORMALIZED):
                inventory.status = ExtractionStatus.PARTIALLY_NORMALIZED

    @classmethod
    def _inventory_interface(cls, extraction, interface):
        candidates = [
            item for item in extraction.inventory_items
            if item.domain == "interfaces"
            and item.name == interface.name
            and item.source_context == interface.source_context
        ]
        layer3 = [
            item for item in candidates
            if item.source_attributes.get("pan_interface_mode") == "layer3"
        ]
        return (layer3 or candidates or [None])[0]

    @staticmethod
    def _add_assignment(profile, interface) -> None:
        attrs = profile.source_attributes
        assigned = attrs.setdefault("pan_management_profile_assigned_interfaces", [])
        if interface.name not in assigned:
            assigned.append(interface.name)
        details = attrs.setdefault("pan_management_profile_assignment_details", [])
        if not any(detail.get("interface_name") == interface.name for detail in details):
            details.append({
                "interface_name": interface.name,
                "interface_source_context": interface.source_context,
                "interface_ip": interface.ip,
                "interface_source_path": interface.source_attributes.get("pan_source_path"),
            })

    @staticmethod
    def _copy_evidence(interface, inventory, evidence: dict[str, Any]) -> None:
        interface.source_attributes.update(evidence)
        if inventory is not None:
            inventory.source_attributes.update(evidence)

    @classmethod
    def correlate_scope(cls, scope: PANScope, extraction: ExtractionResult) -> None:
        context = cls._scope_context(scope)
        profiles: dict[str, list] = {}
        for item in extraction.inventory_items:
            if (
                item.domain == MANAGEMENT_ACCESS_DOMAIN
                and item.source_context == context
                and item.source_attributes.get("pan_management_access_kind") == INTERFACE_MANAGEMENT_PROFILE
                and item.name
            ):
                profiles.setdefault(item.name, []).append(item)

        for interface in extraction.canonical_ir.interfaces:
            if interface.source_context != context or not interface.management_profile:
                continue
            inventory = cls._inventory_interface(extraction, interface)
            candidates = profiles.get(interface.management_profile, [])
            for profile in candidates:
                cls._add_assignment(profile, interface)

            if not candidates:
                cls._copy_evidence(interface, inventory, {
                    "pan_management_profile_resolution": "unresolved",
                    "pan_unresolved_management_profile": interface.management_profile,
                })
                cls._review(interface, inventory, "unresolved-management-profile")
                continue
            if len(candidates) > 1:
                cls._copy_evidence(interface, inventory, {
                    "pan_management_profile_resolution": "ambiguous",
                    "pan_ambiguous_management_profile": interface.management_profile,
                    "pan_ambiguous_management_profile_record_ids": [
                        item.source_record_id for item in candidates
                    ],
                })
                cls._review(interface, inventory, "ambiguous-management-profile")
                continue

            profile = candidates[0]
            attrs = profile.source_attributes
            provenance = {
                "pan_management_profile_resolution": "resolved",
                "pan_management_profile_source_record_id": profile.source_record_id,
                "pan_management_profile_source_path": profile.source_path,
                "pan_management_profile_source_status": profile.status.value,
                "pan_management_profile_source_requires_manual_review": profile.requires_manual_review,
                "pan_effective_management_profile_name": profile.name,
            }
            if profile.status == ExtractionStatus.PARSE_ERROR:
                provenance["pan_invalid_management_profile"] = interface.management_profile
                cls._copy_evidence(interface, inventory, provenance)
                cls._review(interface, inventory, "invalid-management-profile")
                continue

            services = attrs.get("pan_management_profile_services", {})
            derived = [
                field for field in INTERFACE_MANAGEMENT_SERVICE_FIELDS
                if services.get(field) is True
            ]
            presence = attrs.get("pan_management_profile_service_presence", {})
            complete = all(presence.get(field) is True for field in INTERFACE_MANAGEMENT_SERVICE_FIELDS)
            permitted_ips = list(attrs.get("pan_management_profile_permitted_ips", []))
            evidence = {
                **provenance,
                "pan_effective_management_services": dict(services),
                "pan_effective_management_service_presence": dict(presence),
                "pan_effective_management_service_state_complete": complete,
                "pan_effective_management_permitted_ips": permitted_ips,
                "pan_effective_management_permitted_ip_explicit": attrs.get(
                    "pan_management_profile_permitted_ip_explicit", False
                ),
                "pan_effective_management_source_restriction": (
                    "restricted" if permitted_ips else "unrestricted"
                ),
            }
            for key in ("pan_management_profile_unknown_fields", "pan_management_profile_unknown_permitted_ip_fields"):
                if key in attrs:
                    evidence[key] = attrs[key]
            if interface.management_access and interface.management_access != derived:
                evidence["pan_effective_management_access"] = derived
                cls._copy_evidence(interface, inventory, evidence)
                cls._review(interface, inventory, "management-access-correlation-conflict")
                continue
            interface.management_access = derived
            evidence["pan_effective_management_access"] = list(derived)
            cls._copy_evidence(interface, inventory, evidence)
            if not complete:
                cls._review(interface, inventory, "management-access-service-defaults-unresolved")
            if permitted_ips:
                cls._review(interface, inventory, "management-access-source-restrictions")
            if attrs.get("pan_management_profile_unknown_fields") or attrs.get(
                "pan_management_profile_unknown_permitted_ip_fields"
            ):
                cls._review(interface, inventory, "management-access-unknown-profile-fields")


extract_management_access = PANManagementAccessExtractor.extract
