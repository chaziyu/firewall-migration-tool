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
    return _text(element.find(tag)) if element is not None else None


def _values(element: ET.Element, tag: str) -> list[str] | None:
    child = element.find(tag) if element is not None else None
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
    known = {"ip-address", "mac-address", "mac", "description"}
    extra, explicit = _nested_metadata(element, known, {"ip-address": "ip_address", "mac-address": "mac_address"})
    if element.find("mac") is not None:
        explicit.add("mac_address")
    explicit.intersection_update(PANDHCPReservation.model_fields)
    return PANDHCPReservation(
        name=element.get("name"), ip_address=_value(element, "ip-address"), mac_address=_value(element, "mac-address") or _value(element, "mac"),
        description=_value(element, "description"), raw_extra=extra, explicit_fields=explicit,
    )


def _option(element: ET.Element) -> PANDHCPOption:
    known = {"code", "vendor-class-identifier", "inherited", "value-type", "ip-values", "ascii-values", "hex-values", "ip", "ascii", "hex"}
    field_map = {
        "vendor-class-identifier": "vendor_class_identifier", "value-type": "value_type",
        "ip-values": "ip_values", "ascii-values": "ascii_values", "hex-values": "hex_values",
    }
    extra, explicit = _nested_metadata(element, known, field_map)
    explicit.intersection_update(PANDHCPOption.model_fields)
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
    server = element.find("server")
    selected = server is not None
    source = server if selected else element
    extra, explicit = source_fields(
        element,
        spec,
        handled_nested={"server": "server", "reserved": "reservations", "user-defined": "options"},
    )
    if selected:
        explicit.discard("server")
    option = source.find("option") if source is not None else None
    pools = _entries(source, "ip-pool") if source is not None else None
    pool_members = source.find("ip-pool").findall("member") if source is not None and source.find("ip-pool") is not None else []
    reservations = _entries(source, "reservations", "reserved") if source is not None else None
    options = _entries(option, "user-defined") if option is not None else None
    if options is None and not selected:
        options = _entries(source, "options", "user-defined")
    if options is None and option is not None and option.find("user-defined") is not None:
        options = [option.find("user-defined")]
    for alias in ("reserved", "user-defined"):
        extra.pop(alias, None)
    for child, field in ((pools or pool_members, "ip_pools"), (reservations, "reservations"), (options, "options")):
        if child is not None:
            explicit.add(field)

    if selected:
        known_server = {"mode", "probe-ip", "ip-pool", "reserved", "option"}
        server_extra = raw_extra(source, known_server)
        if option is not None:
            option_known = {"lease", "inheritance", "gateway", "subnet-mask", "dns", "wins", "ntp", "pop3-server", "smtp-server", "dns-suffix", "user-defined"}
            option_extra = raw_extra(option, option_known)
            for container, known in ((option.find("lease"), {"unlimited", "timeout"}), (option.find("inheritance"), {"source"}), (option.find("dns"), {"primary", "secondary"})):
                if container is not None:
                    unknown = raw_extra(container, known)
                    if unknown:
                        option_extra[container.tag] = unknown
            if option_extra:
                server_extra["option"] = option_extra
        if server_extra:
            extra["server"] = server_extra

    lease = option.find("lease") if option is not None else None
    lease_type = "unlimited" if lease is not None and lease.find("unlimited") is not None else "timeout" if lease is not None and lease.find("timeout") is not None else _value(element, "lease-type")
    lease_timeout = _value(lease, "timeout") if lease is not None else _value(element, "lease-timeout")
    if selected:
        if element.get("name") is not None:
            explicit.add("interface")
        for tag, field in (("mode", "mode"), ("probe-ip", "probe_ip")):
            if source.find(tag) is not None:
                explicit.add(field)
        if source.find("ip-pool") is not None:
            explicit.add("ip_pools")
        if source.find("reserved") is not None:
            explicit.add("reservations")
        if option is not None:
            for tag, field in (("unlimited", "lease_type"), ("timeout", "lease_type")):
                if option.find(f"lease/{tag}") is not None:
                    explicit.add(field)
            for source_path, field in (("lease/timeout", "lease_timeout"), ("inheritance/source", "inheritance_source"), ("gateway", "gateway"), ("subnet-mask", "subnet_mask"), ("dns/primary", "dns_primary"), ("dns/secondary", "dns_secondary"), ("wins", "wins"), ("ntp", "ntp"), ("pop3-server", "pop3_server"), ("smtp-server", "smtp_server"), ("dns-suffix", "dns_suffix")):
                if option.find(source_path) is not None:
                    explicit.add(field)
    def option_value(tag: str):
        return _value(option, tag) if selected else _value(source, tag)
    def option_values(tag: str):
        return _values(option, tag) if selected else _values(source, tag)

    typed_options = None
    if options is not None:
        typed_options = []
        for source_option in options:
            item = _option(source_option)
            branches = [child for child in source_option if child.tag in {"ip", "ascii", "hex"}]
            if branches:
                branch = branches[0]
                field = {"ip": "ip_values", "ascii": "ascii_values", "hex": "hex_values"}[branch.tag]
                values = [_text(value) or "" for value in branch.findall("member")] or [_text(branch) or ""]
                item = item.model_copy(update={"value_type": branch.tag, field: values, "explicit_fields": item.explicit_fields | {"value_type", field}})
            typed_options.append(item)

    return PANDHCPServer(
        name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order,
        interface=element.get("name") if selected else _value(element, "interface"), mode=_value(source, "mode"), probe_ip=_value(source, "probe-ip"),
        lease_type=lease_type, lease_timeout=lease_timeout,
        inheritance_source=_value(option.find("inheritance"), "source") if selected and option is not None else _value(element, "inheritance-source"),
        gateway=option_value("gateway"), subnet_mask=option_value("subnet-mask"),
        dns_primary=_value(option.find("dns"), "primary") if selected and option is not None else _value(element, "dns-primary"),
        dns_secondary=_value(option.find("dns"), "secondary") if selected and option is not None else _value(element, "dns-secondary"),
        wins=option_values("wins"), ntp=option_values("ntp"),
        pop3_server=option_value("pop3-server"), smtp_server=option_value("smtp-server"),
        dns_suffix=option_value("dns-suffix"),
        ip_pools=([PANDHCPIPPool(value=_text(member), explicit_fields={"value"}) for member in pool_members] if pool_members else [_pool(item) for item in pools] if pools is not None else None),
        reservations=[_reservation(item) for item in reservations] if reservations is not None else None,
        options=typed_options,
        raw_extra=extra, explicit_fields=explicit,
    )
