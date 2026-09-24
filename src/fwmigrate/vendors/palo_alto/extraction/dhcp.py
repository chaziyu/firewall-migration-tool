from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..model import PANDHCPIPPool, PANDHCPOption, PANDHCPReservation, PANDHCPServer
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields


def _text(element: ET.Element | None) -> str | None:
    return (element.text or "").strip() or None if element is not None else None


def _value(element: ET.Element, tag: str) -> str | None:
    return _text(element.find(tag))


def _values(element: ET.Element, tag: str) -> list[str] | None:
    child = element.find(tag)
    if child is None:
        return None
    members = child.findall("member")
    return [_text(member) or member.get("name") or "" for member in members] if members else [_text(child) or ""]


def _nested_metadata(element: ET.Element, known: set[str], field_map: dict[str, str]) -> tuple[dict[str, Any], set[str]]:
    return raw_extra(element, known), {field_map.get(child.tag, child.tag.replace("-", "_")) for child in element if child.tag in known}


def _pool(element: ET.Element) -> PANDHCPIPPool:
    known = {"value", "start-ip", "end-ip"}
    extra, explicit = _nested_metadata(element, known, {"start-ip": "start_ip", "end-ip": "end_ip"})
    return PANDHCPIPPool(
        name=element.get("name"), value=_value(element, "value"), start_ip=_value(element, "start-ip"),
        end_ip=_value(element, "end-ip"), raw_extra=extra, explicit_fields=explicit,
    )


def _reservation(element: ET.Element) -> PANDHCPReservation:
    known = {"ip-address", "mac-address", "description"}
    extra, explicit = _nested_metadata(element, known, {"ip-address": "ip_address", "mac-address": "mac_address"})
    return PANDHCPReservation(
        name=element.get("name"), ip_address=_value(element, "ip-address"), mac_address=_value(element, "mac-address"),
        description=_value(element, "description"), raw_extra=extra, explicit_fields=explicit,
    )


def _option(element: ET.Element) -> PANDHCPOption:
    known = {"code", "vendor-class-identifier", "inherited", "value-type", "ip-values", "ascii-values", "hex-values"}
    field_map = {
        "vendor-class-identifier": "vendor_class_identifier", "value-type": "value_type",
        "ip-values": "ip_values", "ascii-values": "ascii_values", "hex-values": "hex_values",
    }
    extra, explicit = _nested_metadata(element, known, field_map)
    return PANDHCPOption(
        name=element.get("name"), code=_value(element, "code"),
        vendor_class_identifier=_value(element, "vendor-class-identifier"), inherited=_value(element, "inherited"),
        value_type=_value(element, "value-type"), ip_values=_values(element, "ip-values"),
        ascii_values=_values(element, "ascii-values"), hex_values=_values(element, "hex-values"),
        raw_extra=extra, explicit_fields=explicit,
    )


def _entries(element: ET.Element, *tags: str) -> list[ET.Element] | None:
    for tag in tags:
        section = element.find(tag)
        if section is not None:
            return section.findall("entry")
    return None


def extract_dhcp(
    element: ET.Element,
    path: tuple[str, ...],
    context: PANWalkContext,
    source_order: int,
    spec: PANPathSpec,
) -> PANDHCPServer:
    extra, explicit = source_fields(
        element,
        spec,
        handled_nested={"reserved": "reservations", "user-defined": "options"},
    )
    pools = _entries(element, "ip-pool")
    reservations = _entries(element, "reservations", "reserved")
    options = _entries(element, "options", "user-defined")
    for alias in ("reserved", "user-defined"):
        extra.pop(alias, None)
    for child, field in ((pools, "ip_pools"), (reservations, "reservations"), (options, "options")):
        if child is not None:
            explicit.add(field)

    return PANDHCPServer(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        interface=_value(element, "interface"), mode=_value(element, "mode"), probe_ip=_value(element, "probe-ip"),
        lease_type=_value(element, "lease-type"), lease_timeout=_value(element, "lease-timeout"),
        inheritance_source=_value(element, "inheritance-source"), gateway=_value(element, "gateway"),
        subnet_mask=_value(element, "subnet-mask"), dns_primary=_value(element, "dns-primary"),
        dns_secondary=_value(element, "dns-secondary"), wins=_values(element, "wins"), ntp=_values(element, "ntp"),
        pop3_server=_value(element, "pop3-server"), smtp_server=_value(element, "smtp-server"),
        dns_suffix=_value(element, "dns-suffix"), ip_pools=[_pool(item) for item in pools] if pools is not None else None,
        reservations=[_reservation(item) for item in reservations] if reservations is not None else None,
        options=[_option(item) for item in options] if options is not None else None,
        raw_extra=extra, explicit_fields=explicit,
    )
