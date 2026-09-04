"""Check Point Gaia OS CLI and system configuration parser."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import (
    IRConfig,
    IRInterface,
    IRInterfaceSecondaryIP,
    IRMetadata,
    IRRoute,
    IRZone,
)


def _get_or_create_interface(interfaces: Dict[str, Dict[str, Any]], name: str) -> Dict[str, Any]:
    return interfaces.setdefault(
        name, {"name": name, "ips": [], "enabled": True, "source_attributes": {}, "review_reasons": []},
    )


def _create_vlan_interface(
    interfaces: Dict[str, Dict[str, Any]], parent: str, vlan_id: int,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not 1 <= vlan_id <= 4094:
        return None, "invalid-vlan-id"
    _get_or_create_interface(interfaces, parent)
    name = f"{parent}.{vlan_id}"
    existing = interfaces.get(name)
    if existing and existing.get("_vlan_created"):
        return existing, "duplicate-vlan-creation"
    child = _get_or_create_interface(interfaces, name)
    if child.get("parent") not in (None, parent) or child.get("vlanid") not in (None, vlan_id):
        return child, "conflicting-vlan-creation"
    child.update({"parent": parent, "vlanid": vlan_id, "interface_type": "vlan", "_vlan_created": True})
    return child, None


def _mask_to_prefix(mask: str) -> int:
    network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    return network.prefixlen


def _parse_static_route_tokens(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse the stable Gaia route tokens without relying on one positional regex."""
    try:
        tokens = shlex.split(line)
        lowered = [token.lower() for token in tokens]
        if len(tokens) < 4 or lowered[:2] != ["set", "static-route"]:
            return None, "not-static-route"
        result: Dict[str, Any] = {"destination": tokens[2], "raw_command": line, "state": None}
        index = 3
        if index >= len(tokens) or lowered[index] != "nexthop":
            return None, "missing-nexthop"
        index += 1
        if index < len(tokens) and lowered[index] in {"blackhole", "reject"}:
            result["nexthop_type"] = lowered[index]
            index += 1
        elif index + 2 < len(tokens) and lowered[index] == "gateway":
            gateway_kind = lowered[index + 1]
            if gateway_kind == "address":
                result["nexthop_type"] = "gateway"
                result["next_hop"] = tokens[index + 2]
                index += 3
            elif gateway_kind == "logical":
                result["nexthop_type"] = "interface"
                result["interface"] = tokens[index + 2]
                index += 3
            else:
                return None, "unsupported-nexthop-form"
        elif index + 1 < len(tokens) and lowered[index] in {"logical", "interface"}:
            # Historical synthetic syntax; retain it only as review-required evidence.
            result["nexthop_type"] = "interface"
            result["interface"] = tokens[index + 1]
            result["legacy_syntax"] = True
            index += 2
        else:
            return None, "unsupported-nexthop-form"

        unmodeled: Dict[str, Any] = {}
        while index < len(tokens):
            token = tokens[index].lower()
            if token in {"on", "off"}:
                if result["state"] is not None:
                    return None, "duplicate-route-state"
                result["state"] = token
                index += 1
            elif token == "priority":
                if index + 1 >= len(tokens):
                    return None, "missing-route-priority"
                try:
                    priority = int(tokens[index + 1])
                except ValueError:
                    return None, "invalid-route-priority"
                if priority < 0:
                    return None, "invalid-route-priority"
                result["priority"] = priority
                index += 2
            elif token == "scopelocal":
                unmodeled[token] = True
                index += 1
            elif token == "scope-local":
                unmodeled[token] = True
                unmodeled["legacy_syntax"] = True
                index += 1
            elif token in {"rank", "ping", "comment", "comments"}:
                value = tokens[index + 1] if index + 1 < len(tokens) else True
                unmodeled[token] = value
                index += 2 if index + 1 < len(tokens) else 1
            else:
                unmodeled[token] = True
                index += 1
        result["state"] = result["state"] or "on"
        result["unmodeled"] = unmodeled
        return result, None
    except (IndexError, TypeError, ValueError) as exc:
        return None, f"malformed-static-route:{exc}"


def parse_gaia_configuration(
    gaia_text: str,
) -> Tuple[IRMetadata, List[IRInterface], List[IRZone], List[IRRoute], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Parse Gaia OS CLI text configuration (e.g. from 'show configuration')."""
    hostname = "checkpoint-gw"
    interfaces_dict: Dict[str, Dict[str, Any]] = {}
    zones_set: set[str] = set()
    routes: List[IRRoute] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    lines = gaia_text.splitlines()

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        src_path = "gaia/show-configuration"

        # Hostname
        m_host = re.match(r"^set\s+hostname\s+([^\s]+)", line, re.IGNORECASE)
        if m_host:
            hostname = m_host.group(1)
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/system",
                name="hostname",
                source_attributes={"hostname": hostname},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        # Interface definitions
        # e.g. set interface eth0 ipv4-address 10.0.0.1 mask-length 24
        m_if_ip = re.match(
            r"^set\s+interface\s+([^\s]+)\s+ipv4-address\s+([^\s]+)\s+(mask-length|subnet-mask)\s+([^\s]+)$",
            line, re.IGNORECASE,
        )
        if m_if_ip:
            if_name = m_if_ip.group(1)
            ip_str = m_if_ip.group(2)
            mask_kind = m_if_ip.group(3).lower()
            mask_value = m_if_ip.group(4)
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                prefix = int(mask_value) if mask_kind == "mask-length" else _mask_to_prefix(mask_value)
                if not 0 <= prefix <= 32:
                    raise ValueError("IPv4 prefix outside 0..32")
                ipaddress.IPv4Address(ip_str)
                if_data = _get_or_create_interface(interfaces_dict, if_name)
                if_data["ips"].append(f"{ip_str}/{prefix}")
            except (ValueError, TypeError) as exc:
                status = ExtractionStatus.PARSE_ERROR
                notes.append(f"invalid-interface-ip:{exc}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_ip",
                source_attributes={"interface": if_name, "ip": ip_str, mask_kind.replace("-", "_"): mask_value},
                status=status,
                requires_manual_review=(status == ExtractionStatus.PARSE_ERROR),
                notes=notes,
            ))
            continue

        m_if_ip6 = re.match(r"^set\s+interface\s+([^\s]+)\s+ipv6-address\s+([^\s/]+)(?:\s+mask-length\s+|/)(\d+)", line, re.IGNORECASE)
        if m_if_ip6:
            if_name, ip_str, mask_len = m_if_ip6.groups()
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                prefix = int(mask_len)
                if not 0 <= prefix <= 128:
                    raise ValueError("IPv6 prefix outside 0..128")
                ipaddress.IPv6Address(ip_str)
                if_data = _get_or_create_interface(interfaces_dict, if_name)
                if_data["ips"].append(f"{ip_str}/{prefix}")
            except (ValueError, TypeError) as exc:
                status = ExtractionStatus.PARSE_ERROR
                notes.append(f"invalid-interface-ipv6:{exc}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_ipv6", source_type="gaia-interface-ipv6",
                source_attributes={"interface": if_name, "ipv6": ip_str, "mask_length": mask_len},
                status=status, requires_manual_review=(status == ExtractionStatus.PARSE_ERROR), notes=notes,
            ))
            continue

        # Interface state
        m_if_state = re.match(r"^set\s+interface\s+([^\s]+)\s+state\s+(on|off)", line, re.IGNORECASE)
        if m_if_state:
            if_name = m_if_state.group(1)
            state = m_if_state.group(2).lower()
            if_data = _get_or_create_interface(interfaces_dict, if_name)
            if_data["enabled"] = (state == "on")
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_state", source_type="gaia-interface-state",
                source_attributes={"interface": if_name, "state": state},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        # Interface comment
        m_if_comm = re.match(r'^set\s+interface\s+([^\s]+)\s+comments?\s+"?([^"]*)"?', line, re.IGNORECASE)
        if m_if_comm:
            if_name = m_if_comm.group(1)
            comment = m_if_comm.group(2)
            if_data = _get_or_create_interface(interfaces_dict, if_name)
            if_data["description"] = comment
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_comment", source_type="gaia-interface-comment",
                source_attributes={"interface": if_name, "comment": comment},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        m_if_behavior = re.match(
            r"^set\s+interface\s+([^\s]+)\s+(mtu|link-speed|speed|duplex|auto-negotiation|mac-addr|mac-address|ipv6-autoconfig|monitor-mode)\s+(.+)$",
            line, re.IGNORECASE,
        )
        if m_if_behavior:
            if_name, setting, value = m_if_behavior.groups()
            setting = setting.lower()
            if_data = _get_or_create_interface(interfaces_dict, if_name)
            if_data["source_attributes"][setting] = value
            reason = (
                "legacy-synthetic-gaia-interface-setting"
                if setting in {"speed", "duplex"}
                else f"unmodeled-interface-setting:{setting}"
            )
            if_data["review_reasons"].append(reason)
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_{setting}",
                source_type=(
                    "gaia-interface-setting-legacy-compatibility"
                    if setting in {"speed", "duplex"}
                    else "gaia-interface-setting"
                ),
                source_attributes={"interface": if_name, "setting": setting, "value": value},
                status=ExtractionStatus.PARTIALLY_NORMALIZED,
                requires_manual_review=True, notes=[reason],
            ))
            continue

        # Official R81 loopback creation; later `set interface <name> ...`
        # commands merge into the same explicitly named interface.
        m_loopback = re.match(
            r"^add\s+interface\s+([^\s]+)\s+loopback\s+([^\s/]+)/([0-9]+)$",
            line, re.IGNORECASE,
        )
        if m_loopback:
            if_name, ip_str, prefix_raw = m_loopback.groups()
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                prefix = int(prefix_raw)
                if not 0 <= prefix <= 32:
                    raise ValueError("IPv4 prefix outside 0..32")
                ipaddress.IPv4Address(ip_str)
                if_data = _get_or_create_interface(interfaces_dict, if_name)
                if_data["interface_type"] = "loopback"
                if_data["ips"].append(f"{ip_str}/{prefix}")
                if_data["source_attributes"]["raw_creation_command"] = line
            except (ValueError, TypeError) as exc:
                status = ExtractionStatus.PARSE_ERROR
                notes.append(f"invalid-loopback-ip:{exc}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_loopback", source_type="gaia-loopback",
                source_attributes={
                    "interface": if_name,
                    "ipv4": ip_str,
                    "prefix": prefix_raw,
                    "raw_command": line,
                },
                status=status,
                requires_manual_review=(status == ExtractionStatus.PARSE_ERROR),
                notes=notes,
            ))
            continue

        m_logical_inventory = re.match(
            r"^(add|set)\s+(bonding\s+group|bridging\s+group|bridge)\s+(.+)$", line, re.IGNORECASE,
        )
        if m_logical_inventory:
            operation, object_type, remainder = m_logical_inventory.groups()
            object_type = object_type.lower()
            legacy = object_type == "bridge"
            note = (
                "legacy-synthetic-gaia-bridge-syntax"
                if legacy else f"unmodeled-logical-interface:{object_type}"
            )
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface-inventory",
                name=f"gaia_{object_type.replace(' ', '_')}_{line_num}",
                source_type=(
                    "gaia-bridge-legacy-compatibility"
                    if legacy else f"gaia-{object_type.replace(' ', '-')}"
                ),
                source_attributes={"operation": operation.lower(), "arguments": remainder, "raw_command": line},
                status=(
                    ExtractionStatus.PARTIALLY_NORMALIZED
                    if legacy else ExtractionStatus.EXTRACT_ONLY
                ),
                requires_manual_review=True,
                notes=[note],
            ))
            continue

        m_vlan = re.match(r"^add\s+interface\s+([^\s]+)\s+vlan\s+([^\s]+)$", line, re.IGNORECASE)
        if m_vlan:
            parent, vlan_raw = m_vlan.groups()
            try:
                vlan_id = int(vlan_raw)
                if_data, vlan_error = _create_vlan_interface(interfaces_dict, parent, vlan_id)
            except ValueError:
                vlan_id, if_data, vlan_error = -1, None, "invalid-vlan-id"
            status = ExtractionStatus.NORMALIZED if vlan_error is None else ExtractionStatus.PARSE_ERROR
            if_name = f"{parent}.{vlan_raw}"
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_vlan", source_type="gaia-vlan",
                source_attributes={"parent": parent, "interface": if_name, "vlan_id": vlan_raw}, status=status,
                requires_manual_review=(status == ExtractionStatus.PARSE_ERROR),
                notes=[] if status == ExtractionStatus.NORMALIZED else [str(vlan_error)],
            ))
            continue

        # Explicit legacy-fixture compatibility only. Real R81 Gaia creation is
        # `add interface <parent> vlan <id>` and is handled above.
        m_legacy_vlan = re.match(r"^set\s+interface\s+([^\s]+)\s+vlan-id\s+([^\s]+)$", line, re.IGNORECASE)
        if m_legacy_vlan:
            if_name, vlan_raw = m_legacy_vlan.groups()
            try:
                vlan_id = int(vlan_raw)
                if "." not in if_name:
                    raise ValueError("legacy VLAN name has no parent suffix")
                parent = if_name.rsplit(".", 1)[0]
                child, vlan_error = _create_vlan_interface(interfaces_dict, parent, vlan_id)
                if vlan_error:
                    raise ValueError(vlan_error)
                status, notes = ExtractionStatus.PARTIALLY_NORMALIZED, ["legacy-synthetic-gaia-vlan-syntax"]
            except ValueError as exc:
                status, notes = ExtractionStatus.PARSE_ERROR, [f"invalid-legacy-vlan:{exc}"]
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_legacy_vlan", source_type="gaia-vlan-legacy-compatibility",
                source_attributes={"raw_command": line, "vlan_id": vlan_raw}, status=status,
                requires_manual_review=True, notes=notes,
            ))
            continue

        # Interface security zone binding
        m_if_zone = re.match(r"^set\s+interface\s+([^\s]+)\s+security-zone\s+([^\s]+)", line, re.IGNORECASE)
        if m_if_zone:
            if_name = m_if_zone.group(1)
            zone_name = m_if_zone.group(2)
            if_data = _get_or_create_interface(interfaces_dict, if_name)
            if_data["zone"] = zone_name
            if_data["review_reasons"].append("legacy-synthetic-gaia-security-zone")
            zones_set.add(zone_name)
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/interface/{if_name}/zone",
                name=f"{if_name}_zone_{zone_name}",
                source_attributes={"interface": if_name, "security_zone": zone_name},
                status=ExtractionStatus.PARTIALLY_NORMALIZED,
                requires_manual_review=True,
                notes=["legacy-synthetic-gaia-security-zone"],
            ))
            continue

        # Static routes
        # e.g. set static-route default nexthop gateway address 192.168.1.1 on
        # e.g. set static-route 10.0.0.0/8 nexthop gateway address 192.168.1.254 on
        if line.lower().startswith("set static-route "):
            parsed_route, route_error = _parse_static_route_tokens(line)
            dest_raw = parsed_route.get("destination") if parsed_route else "<unknown>"
            gw_ip = parsed_route.get("next_hop") if parsed_route else None
            state = parsed_route.get("state", "on") if parsed_route else "on"
            dest = "0.0.0.0/0" if dest_raw.lower() in ("default", "0.0.0.0/0") else dest_raw
            route_name = f"static_{dest.replace('/', '_')}_{gw_ip or (parsed_route or {}).get('interface') or (parsed_route or {}).get('nexthop_type', 'unknown')}"
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                if route_error:
                    raise ValueError(route_error)
                ipaddress.ip_network(dest, strict=False)
                if gw_ip is not None:
                    ipaddress.ip_address(gw_ip)
                unmodeled = parsed_route.get("unmodeled", {})
                nexthop_type = parsed_route.get("nexthop_type")
                if nexthop_type in {"blackhole", "reject"} or unmodeled or parsed_route.get("legacy_syntax"):
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    notes.extend([f"unmodeled-route-setting:{key}" for key in unmodeled])
                    if nexthop_type in {"blackhole", "reject"}:
                        notes.append(f"unmodeled-route-nexthop:{nexthop_type}")
                elif state == "on":
                    routes.append(IRRoute(
                        name=route_name, destination=dest, next_hop=gw_ip,
                        interface=parsed_route.get("interface"), priority=parsed_route.get("priority"),
                        source_attributes={"raw_command": line},
                    ))
                else:
                    status = ExtractionStatus.EXTRACT_ONLY
                    notes.append("disabled-static-route")
            except ValueError as exc:
                status = ExtractionStatus.PARSE_ERROR
                notes.append(f"invalid-static-route:{exc}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/routing",
                name=route_name,
                source_attributes=parsed_route or {"raw_command": line},
                status=status, requires_manual_review=(status in {ExtractionStatus.PARSE_ERROR, ExtractionStatus.PARTIALLY_NORMALIZED}), notes=notes,
            ))
            continue

        m_dns = re.match(r"^set\s+dns\s+([^\s]+)\s+(.+)$", line, re.IGNORECASE)
        if m_dns:
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/dns", name=f"dns_{m_dns.group(1)}",
                source_type="gaia-dns", source_attributes={"setting": m_dns.group(1), "value": m_dns.group(2)},
                status=ExtractionStatus.EXTRACT_ONLY,
                notes=["Gaia DNS setting preserved as extract-only"],
            ))
            continue

        # Generic / Other Gaia commands recorded as leaf items
        inventory_items.append(SourceInventoryItem(
            domain="gaia",
            source_path=src_path,
            name=f"gaia_cmd_{line_num}",
            source_attributes={"raw_command": line},
            status=ExtractionStatus.EXTRACT_ONLY,
        ))

    ir_interfaces: List[IRInterface] = []
    for if_name, data in interfaces_dict.items():
        ips = data.get("ips", [])
        ir_interfaces.append(IRInterface(
            name=if_name,
            status=data.get("enabled", True),
            ip=ips[0] if ips else None,
            secondary_ips=[IRInterfaceSecondaryIP(ip=ip) for ip in ips[1:]],
            zone=data.get("zone"),
            description=data.get("description"),
            parent=data.get("parent"), vlanid=data.get("vlanid"),
            interface_type=data.get("interface_type") or ("vlan" if data.get("vlanid") else "physical"),
            requires_manual_review=bool(data.get("review_reasons")),
            parse_errors=list(data.get("review_reasons", [])),
            source_attributes=dict(data.get("source_attributes", {})),
        ))

    ir_zones: List[IRZone] = [
        IRZone(name=z, interfaces=[iface.name for iface in ir_interfaces if iface.zone == z])
        for z in sorted(zones_set)
    ]

    metadata = IRMetadata(
        hostname=hostname,
        source_vendor="checkpoint",
    )

    return metadata, ir_interfaces, ir_zones, routes, inventory_items, unsupported_items
