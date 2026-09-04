"""Typed PAN-OS device-level system settings projection."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import (
    IRDNSSettings,
    IRManagementPlaneSettings,
    IRManagementServiceRoute,
    IRNTPServer,
    IRNTPSettings,
    IRSystemSettings,
)
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes

from .extraction import add_source_section, record_extract_only, record_normalized, record_parse_error, record_partial
from .management_access import PANManagementAccessExtractor
from .source_model import PANScope
from .xml_utils import structured_xml_capture


SYSTEM_SETTINGS_HANDLED_CHILDREN = {
    "hostname", "timezone", "dns-setting", "ntp-servers", "route",
}
SYSTEM_SETTINGS_DOMAIN = "system_settings"


def _text(node: Optional[ET.Element]) -> Optional[str]:
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def _safe_capture(node: Optional[ET.Element]) -> Any:
    captured = structured_xml_capture(node) or {}

    def redact_ntp_keys(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if str(key).lower().replace("_", "-") in {
                    "key", "authentication-key", "auth-key",
                } else redact_ntp_keys(child)
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [redact_ntp_keys(child) for child in value]
        return value

    return sanitize_source_attributes(redact_ntp_keys(captured))


def _scope_context(scope: PANScope) -> str:
    return (
        f"{scope.kind}:{scope.name}:device:{scope.device_serial}"
        if scope.device_serial else f"{scope.kind}:{scope.name}"
    )


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _valid_source_address(value: str) -> bool:
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
    return True


def _record_owned(
    scope: PANScope,
    extraction,
    path: str,
    node: ET.Element,
    status: ExtractionStatus,
    notes: list[str],
    name: Optional[str] = None,
) -> None:
    recorder = {
        ExtractionStatus.NORMALIZED: record_normalized,
        ExtractionStatus.PARTIALLY_NORMALIZED: record_partial,
        ExtractionStatus.PARSE_ERROR: record_parse_error,
    }.get(status, record_extract_only)
    recorder(
        extraction,
        SYSTEM_SETTINGS_DOMAIN,
        path,
        scope,
        name,
        {"pan_source_entry": _safe_capture(node)},
        notes=notes,
        **({"requires_manual_review": True} if status == ExtractionStatus.EXTRACT_ONLY else {}),
    )


def _merge_value(existing: Any, value: Any, conflicts: list[str], field: str) -> Any:
    if existing is None:
        return value
    if value is None or existing == value:
        return existing
    conflicts.append(field)
    return None


def _project_management(scope: PANScope, system_root: ET.Element) -> IRManagementPlaneSettings:
    management = IRManagementPlaneSettings()
    source = management.source_attributes

    scalar_fields = {
        "ip-address": "ipv4_address",
        "netmask": "netmask",
        "default-gateway": "default_gateway",
        "ipv6-address": "ipv6_address",
        "ipv6-default-gateway": "ipv6_default_gateway",
    }
    for tag, field in scalar_fields.items():
        node = system_root.find(f"./{tag}")
        if node is None:
            continue
        evidence, issues, _ = PANManagementAccessExtractor._system_scalar_evidence(
            scope, "management-interface-access", f"deviceconfig/system/{tag}", tag, node
        )
        source[tag] = evidence
        value = _text(node)
        if not issues:
            setattr(management, field, value)

    choices = {
        "type": ("address_type", "pan_system_management_type"),
        "ipv6-type": ("ipv6_address_type", "pan_system_management_ipv6_type"),
        "ipv6-gw-type": ("ipv6_gateway_type", "pan_system_management_ipv6_gateway_type"),
    }
    for tag, (field, evidence_key) in choices.items():
        node = system_root.find(f"./{tag}")
        if node is None:
            continue
        key, supported = {
            "type": ("pan_system_management_type", ("static", "dhcp-client")),
            "ipv6-type": ("pan_system_management_ipv6_type", ("static", "dynamic")),
            "ipv6-gw-type": ("pan_system_management_ipv6_gateway_type", ("static", "dynamic")),
        }[tag]
        evidence, issues, _ = PANManagementAccessExtractor._system_choice_evidence(
            scope, f"deviceconfig/system/{tag}", node, key, supported
        )
        source[tag] = evidence
        if not issues:
            setattr(management, field, evidence.get(evidence_key))

    node = system_root.find("./ipv6-enable")
    if node is not None:
        evidence, issues, _ = PANManagementAccessExtractor._system_boolean_evidence(
            scope, "deviceconfig/system/ipv6-enable", node
        )
        source["ipv6-enable"] = evidence
        if not issues:
            management.ipv6_enabled = evidence.get("pan_system_management_ipv6_enabled")

    service = system_root.find("./service")
    if service is not None:
        evidence, _, _ = PANManagementAccessExtractor._system_service_evidence(
            scope, "deviceconfig/system/service", service
        )
        source["service"] = evidence
        management.services.update(evidence.get("pan_system_management_services", {}))

    permitted_ip = system_root.find("./permitted-ip")
    if permitted_ip is not None:
        evidence, _, _ = PANManagementAccessExtractor._system_permitted_ip_evidence(
            scope, "deviceconfig/system/permitted-ip", permitted_ip
        )
        source["permitted-ip"] = evidence
        management.permitted_ips = [
            value for value in evidence.get("pan_system_management_permitted_ips", [])
            if PANManagementAccessExtractor._valid_permitted_ip(value)
        ]
    return management


def _project_dns(scope: PANScope, dns_node: ET.Element, extraction) -> IRDNSSettings:
    primary = _text(dns_node.find("./servers/primary"))
    secondary = _text(dns_node.find("./servers/secondary"))
    settings = IRDNSSettings(
        primary=primary,
        secondary=secondary,
        source_attributes={"pan_source_entry": _safe_capture(dns_node)},
    )
    invalid = [value for value in (primary, secondary) if value and not _valid_ip(value)]
    notes = ["PAN-OS DNS settings retained with typed primary and secondary values."]
    unknown = [child.tag for child in dns_node if child.tag != "servers"]
    if unknown:
        notes.append("Unknown DNS settings were retained for review: " + ", ".join(unknown))
    if invalid:
        notes.append("DNS values are not valid IP addresses.")
    status = ExtractionStatus.PARTIALLY_NORMALIZED if invalid or unknown else ExtractionStatus.NORMALIZED
    _record_owned(scope, extraction, "deviceconfig/system/dns-setting", dns_node, status, notes)
    add_source_section(
        extraction, "deviceconfig/system/dns-setting", status, 1, 1, 1 if status == ExtractionStatus.NORMALIZED else 0,
        "extract_system_settings", source_context=f"{scope.kind}:{scope.name}",
    )
    return settings


def _project_ntp(scope: PANScope, ntp_node: ET.Element, extraction) -> IRNTPSettings:
    servers: list[IRNTPServer] = []
    review_reasons: list[str] = []
    source_servers = []
    unknown = [
        child.tag for child in ntp_node
        if child.tag not in {"primary-ntp-server", "secondary-ntp-server"}
    ]
    if unknown:
        review_reasons.append("unknown NTP settings: " + ", ".join(unknown))
    for role, tag in (("primary", "primary-ntp-server"), ("secondary", "secondary-ntp-server")):
        node = ntp_node.find(f"./{tag}")
        if node is None:
            continue
        address = _text(node.find("./ntp-server-address"))
        auth_node = node.find("./authentication-type")
        auth_children = list(auth_node) if auth_node is not None else []
        auth_type = auth_children[0].tag if len(auth_children) == 1 else None
        reasons = []
        if address is None:
            reasons.append(f"{role} NTP server is missing ntp-server-address")
        if auth_node is not None and len(auth_children) != 1:
            reasons.append(f"{role} NTP authentication-type is ambiguous")
        review_reasons.extend(reasons)
        source_servers.append(_safe_capture(node))
        servers.append(IRNTPServer(
            role=role,
            address=address,
            authentication_type=auth_type,
            source_attributes={"pan_source_entry": _safe_capture(node), "review_reasons": reasons},
        ))

    settings = IRNTPSettings(
        servers=servers,
        source_attributes={
            "pan_source_entry": _safe_capture(ntp_node),
            "pan_servers": source_servers,
            "review_reasons": review_reasons,
        },
    )
    notes = ["PAN-OS NTP settings are partially normalized; authentication semantics require review."]
    notes.extend(review_reasons)
    _record_owned(
        scope, extraction, "deviceconfig/system/ntp-servers", ntp_node,
        ExtractionStatus.PARTIALLY_NORMALIZED, notes,
    )
    add_source_section(
        extraction, "deviceconfig/system/ntp-servers", ExtractionStatus.PARTIALLY_NORMALIZED,
        len(servers), len(servers), 0,
        "extract_system_settings", source_context=f"{scope.kind}:{scope.name}",
    )
    return settings


def _project_routes(scope: PANScope, route_node: ET.Element, extraction) -> list[IRManagementServiceRoute]:
    routes = []
    entries = list(route_node.findall("./service/entry"))
    name_counts = {}
    for entry in entries:
        name_counts[entry.get("name")] = name_counts.get(entry.get("name"), 0) + 1
    for child in route_node:
        if child.tag == "service":
            continue
        _record_owned(
            scope, extraction, f"deviceconfig/system/route/{child.tag}", child,
            ExtractionStatus.PARSE_ERROR,
            [f"Unhandled PAN-OS management service-route child: {child.tag}."],
        )
    seen_names = {}
    for entry in entries:
        name = entry.get("name")
        address = _text(entry.find("./source/address"))
        interface = _text(entry.find("./source/interface"))
        reasons = []
        if not name:
            reasons.append("management service route is missing name")
        if not address:
            reasons.append("management service route is missing source address")
        elif not _valid_source_address(address):
            reasons.append("management service route has malformed source address")
        if not interface:
            reasons.append("management service route is missing source interface")
        route = IRManagementServiceRoute(
            name=name,
            source_context=_scope_context(scope),
            source_address=address,
            source_interface=interface,
            review_reasons=reasons,
            source_attributes={"pan_source_entry": _safe_capture(entry)},
        )
        routes.append(route)
        seen_names[name] = seen_names.get(name, 0) + 1
        entry_path = (
            f"deviceconfig/system/route/service/entry[@name='{name}']"
            if name else "deviceconfig/system/route/service/entry"
        )
        if name_counts[name] > 1:
            entry_path += f"[{seen_names[name]}]"
        _record_owned(
            scope, extraction,
            entry_path,
            entry, ExtractionStatus.EXTRACT_ONLY,
            ["PAN-OS management service route is source-only and separate from transit routes.", *reasons], name,
        )
    add_source_section(
        extraction, "deviceconfig/system/route/service", ExtractionStatus.EXTRACT_ONLY,
        len(entries), len(routes), 0, "extract_system_settings",
        source_context=f"{scope.kind}:{scope.name}",
    )
    return routes


def extract_system_settings(scope: PANScope, device_root: ET.Element, extraction) -> None:
    system_root = device_root.find("./deviceconfig/system")
    if system_root is None:
        return

    ir = extraction.canonical_ir
    current = ir.system_settings or IRSystemSettings()
    source = current.source_attributes
    conflicts: list[str] = []
    prior_presence = source.get("pan_management_plane_presence_by_device", {})
    presence = {
        tag: system_root.find(f"./{tag}") is not None
        for tag in (
            "ip-address", "netmask", "default-gateway", "type", "ipv6-address",
            "ipv6-default-gateway", "ipv6-enable", "ipv6-type", "ipv6-gw-type",
            "service", "permitted-ip",
        )
    }
    source["pan_management_plane_presence"] = presence
    source.setdefault("pan_management_plane_presence_by_device", {})[_scope_context(scope)] = presence

    for tag, field in (("hostname", "hostname"), ("timezone", "timezone")):
        node = system_root.find(f"./{tag}")
        if node is None:
            continue
        value = _text(node)
        setattr(current, field, _merge_value(getattr(current, field), value, conflicts, field))
        source[tag] = {"pan_source_entry": _safe_capture(node), "explicit": value is not None}
        _record_owned(
            scope, extraction, f"deviceconfig/system/{tag}", node,
            ExtractionStatus.NORMALIZED, [f"PAN-OS {tag} projected into typed system settings."],
        )
        add_source_section(
            extraction, f"deviceconfig/system/{tag}", ExtractionStatus.NORMALIZED,
            1, 1, 1, "extract_system_settings", source_context=f"{scope.kind}:{scope.name}",
        )

    management = _project_management(scope, system_root)
    current.management_plane = management if current.management_plane is None else current.management_plane
    if current.management_plane is not management:
        fields = {
            "ipv4_address": "ip-address", "netmask": "netmask",
            "default_gateway": "default-gateway", "address_type": "type",
            "ipv6_address": "ipv6-address", "ipv6_default_gateway": "ipv6-default-gateway",
            "ipv6_enabled": "ipv6-enable", "ipv6_address_type": "ipv6-type",
            "ipv6_gateway_type": "ipv6-gw-type",
        }
        for field, tag in fields.items():
            if any(previous.get(tag) != presence.get(tag) for previous in prior_presence.values()):
                setattr(current.management_plane, field, None)
                conflicts.append(f"management_plane.{field}")
            else:
                setattr(current.management_plane, field, _merge_value(
                    getattr(current.management_plane, field), getattr(management, field),
                    conflicts, f"management_plane.{field}"
                ))
        prior_service_presence = any(previous.get("service") for previous in prior_presence.values())
        if prior_presence and prior_service_presence != presence.get("service", False):
            current.management_plane.services.clear()
            conflicts.append("management_plane.services")
        for key, value in management.services.items():
            if key in current.management_plane.services and current.management_plane.services[key] != value:
                conflicts.append(f"management_plane.services.{key}")
                del current.management_plane.services[key]
            else:
                current.management_plane.services[key] = value
        prior_permitted_presence = any(previous.get("permitted-ip") for previous in prior_presence.values())
        if prior_presence and prior_permitted_presence != presence.get("permitted-ip", False):
            current.management_plane.permitted_ips = []
            conflicts.append("management_plane.permitted_ips")
        elif current.management_plane.permitted_ips != management.permitted_ips:
            current.management_plane.permitted_ips = []
            conflicts.append("management_plane.permitted_ips")
    source["management_plane"] = management.source_attributes

    dns_node = system_root.find("./dns-setting")
    if dns_node is not None:
        dns = _project_dns(scope, dns_node, extraction)
        if ir.dns_settings is None:
            ir.dns_settings = dns
        else:
            ir.dns_settings.primary = _merge_value(ir.dns_settings.primary, dns.primary, conflicts, "dns.primary")
            ir.dns_settings.secondary = _merge_value(ir.dns_settings.secondary, dns.secondary, conflicts, "dns.secondary")
            ir.dns_settings.source_attributes.update(dns.source_attributes)

    ntp_node = system_root.find("./ntp-servers")
    if ntp_node is not None:
        ntp = _project_ntp(scope, ntp_node, extraction)
        if ir.ntp_settings is None:
            ir.ntp_settings = ntp
        else:
            ir.ntp_settings.servers.extend(ntp.servers)
            ir.ntp_settings.source_attributes.setdefault("pan_source_entries", []).append(ntp.source_attributes)

    route_node = system_root.find("./route")
    if route_node is not None:
        ir.management_service_routes.extend(_project_routes(scope, route_node, extraction))

    if conflicts:
        source["pan_multiple_device_conflicts"] = sorted(set(conflicts))
    current.source_attributes = source
    ir.system_settings = current
