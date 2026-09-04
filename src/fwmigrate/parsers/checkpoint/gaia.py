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
from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
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


def _merge_interface_records(
    interfaces: Dict[str, Dict[str, Any]], source_name: str, target_name: str,
) -> Dict[str, Any]:
    if source_name == target_name:
        return _get_or_create_interface(interfaces, target_name)
    source = interfaces.pop(source_name, {})
    target = _get_or_create_interface(interfaces, target_name)
    target["ips"] = list(dict.fromkeys(target.get("ips", []) + source.get("ips", [])))
    target["source_attributes"] = {
        **source.get("source_attributes", {}), **target.get("source_attributes", {}),
    }
    target["review_reasons"] = list(dict.fromkeys(
        source.get("review_reasons", []) + target.get("review_reasons", []),
    ))
    for key, value in source.items():
        if key not in {"name", "ips", "source_attributes", "review_reasons"}:
            if target.get(key) in (None, [], {}):
                target[key] = value
    target["name"] = target_name
    return target


def _interface_for_command(interfaces: Dict[str, Dict[str, Any]], name: str) -> Dict[str, Any]:
    # The loopback creation command does not include Gaia's generated loopNN
    # name. Bind the placeholder when a later/earlier command exposes it.
    if re.fullmatch(r"loop\d+", name, re.IGNORECASE):
        pending = interfaces.get("lo")
        if pending and pending.get("_loopback_name_pending"):
            return _merge_interface_records(interfaces, "lo", name)
    return _get_or_create_interface(interfaces, name)


def _get_or_create_logical_group(
    groups: Dict[str, Dict[str, Any]], group_id: str, prefix: str, interface_type: str,
) -> Dict[str, Any]:
    group = groups.setdefault(
        group_id,
        {
            "id": int(group_id),
            "name": f"{prefix}{group_id}",
            "interface_type": interface_type,
            "members": [],
            "member_states": {},
            "settings": {},
            "raw_commands": [],
            "review_reasons": [],
        },
    )
    return group


def _add_group_member(group: Dict[str, Any], member: str) -> None:
    if member not in group["members"]:
        group["members"].append(member)


def _logical_inventory_item(
    line: str, line_num: int, source_path: str, source_type: str, attributes: Dict[str, Any],
) -> SourceInventoryItem:
    return SourceInventoryItem(
        domain="gaia",
        source_path=f"{source_path}/interface-inventory",
        name=f"gaia_{source_type.replace('-', '_')}_{line_num}",
        source_type=source_type,
        source_attributes={**attributes, "raw_command": line},
        status=ExtractionStatus.PARTIALLY_NORMALIZED,
        requires_manual_review=True,
        notes=["logical interface behavior requires target review"],
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
    """Parse IPv4/IPv6 Gaia route tokens without relying on one positional regex."""
    try:
        tokens = shlex.split(line)
        lowered = [token.lower() for token in tokens]
        if lowered[:3] == ["set", "ipv6", "static-route"]:
            family, destination_index = "ipv6", 3
        elif lowered[:2] == ["set", "static-route"]:
            family, destination_index = "ipv4", 2
        else:
            return None, "not-static-route"
        if len(tokens) <= destination_index:
            return None, "missing-route-destination"

        result: Dict[str, Any] = {
            "address_family": family,
            "destination": tokens[destination_index],
            "raw_command": line,
            "state": None,
        }
        unmodeled: Dict[str, Any] = {}
        index = destination_index + 1
        while index < len(tokens):
            token = tokens[index].lower()

            if token == "nexthop":
                if index + 1 >= len(tokens):
                    return None, "missing-nexthop"
                kind = lowered[index + 1]
                if kind in {"blackhole", "reject"}:
                    result["nexthop_type"] = kind
                    index += 2
                elif kind == "gateway":
                    value_index = index + 2
                    if value_index >= len(tokens):
                        return None, "missing-gateway"
                    gateway_kind = lowered[value_index]
                    if gateway_kind in {"address", "logical"}:
                        value_index += 1
                        if value_index >= len(tokens):
                            return None, "missing-gateway-value"
                    elif gateway_kind == "interface":
                        value_index += 1
                        if value_index >= len(tokens):
                            return None, "missing-gateway-interface"
                    if gateway_kind in {"logical", "interface"}:
                        result["nexthop_type"] = "interface"
                        result["interface"] = tokens[value_index]
                    else:
                        result["nexthop_type"] = "gateway"
                        result["next_hop"] = tokens[value_index]
                        if value_index + 2 < len(tokens) and lowered[value_index + 1] == "interface":
                            result["interface"] = tokens[value_index + 2]
                            value_index += 2
                    index = value_index + 1
                elif kind in {"logical", "interface"} and index + 2 < len(tokens):
                    # Historical synthetic syntax; retain it only as review-required evidence.
                    result["nexthop_type"] = "interface"
                    result["interface"] = tokens[index + 2]
                    if kind == "logical":
                        result["legacy_syntax"] = True
                    index += 3
                else:
                    return None, "unsupported-nexthop-form"
            elif token == "rank":
                result["nexthop_type"] = "rank"
                if index + 1 >= len(tokens):
                    return None, "missing-route-rank"
                unmodeled["rank"] = tokens[index + 1]
                index += 2
            elif token in {"comment", "comments"}:
                if index + 1 >= len(tokens):
                    return None, "missing-route-comment"
                result["comment"] = None if lowered[index + 1] == "off" else tokens[index + 1]
                unmodeled[token] = result["comment"]
                index += 2
            elif token == "scopelocal":
                value = tokens[index + 1] if index + 1 < len(tokens) and lowered[index + 1] in {"on", "off"} else True
                unmodeled[token] = value
                index += 2 if value is not True else 1
            elif token in {"ping", "ping6"}:
                value = tokens[index + 1] if index + 1 < len(tokens) and lowered[index + 1] in {"on", "off"} else True
                unmodeled[token] = value
                index += 2 if value is not True else 1
            elif token == "monitored-ip":
                if index + 1 >= len(tokens):
                    return None, "missing-monitored-ip"
                monitor = {"address": tokens[index + 1]}
                if index + 2 < len(tokens) and lowered[index + 2] in {"on", "off"}:
                    monitor["state"] = lowered[index + 2]
                    index += 3
                else:
                    index += 2
                unmodeled.setdefault(token, []).append(monitor)
            elif token == "monitored-ip-option":
                if index + 1 >= len(tokens):
                    return None, "missing-monitored-ip-option"
                option = tokens[index + 1]
                index += 2
                if lowered[index - 1] == "force-if-symmetry" and index < len(tokens) and lowered[index] in {"on", "off"}:
                    option = f"{option} {lowered[index]}"
                    index += 1
                unmodeled[token] = option
            elif token in {"on", "off"}:
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
            elif token == "scope-local":
                unmodeled[token] = True
                unmodeled["legacy_syntax"] = True
                index += 1
            else:
                value = tokens[index + 1] if index + 1 < len(tokens) else True
                unmodeled[token] = value
                index += 2 if value is not True else 1
        result["unmodeled"] = unmodeled
        return result, None
    except (IndexError, TypeError, ValueError) as exc:
        return None, f"malformed-static-route:{exc}"


def parse_gaia_configuration(
    gaia_text: str,
    *,
    domain: Optional[str] = None,
    gateway: Optional[str] = None,
    source_response: Optional[str] = None,
    cluster_member: Optional[str] = None,
) -> Tuple[IRMetadata, List[IRInterface], List[IRZone], List[IRRoute], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Parse Gaia OS CLI text configuration (e.g. from 'show configuration')."""
    hostname = "checkpoint-gw"
    interfaces_dict: Dict[str, Dict[str, Any]] = {}
    bonding_groups: Dict[str, Dict[str, Any]] = {}
    bridging_groups: Dict[str, Dict[str, Any]] = {}
    zones_set: set[str] = set()
    routes: List[IRRoute] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []
    route_name_counts: Dict[str, int] = {}

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

        # Bonding groups. Gaia names these interfaces bond<ID>.
        m_bond = re.match(
            r"^(add|set)\s+bonding\s+group\s+(\d+)(?:\s+(.+))?$", line, re.IGNORECASE,
        )
        if m_bond:
            operation, group_id, remainder = m_bond.groups()
            bond = _get_or_create_logical_group(bonding_groups, group_id, "bond", "aggregate")
            bond["raw_commands"].append(line)
            tokens = shlex.split(remainder or "")
            attributes: Dict[str, Any] = {"bonding_group_id": int(group_id), "operation": operation.lower()}
            if operation.lower() == "add" and not tokens:
                pass
            elif tokens and tokens[0].lower() == "interface" and len(tokens) >= 2:
                member = tokens[1]
                _add_group_member(bond, member)
                member_data = _get_or_create_interface(interfaces_dict, member)
                member_data["source_attributes"].setdefault("bonding_groups", []).append(int(group_id))
                attributes["member_interface"] = member
                if len(tokens) >= 4 and tokens[2].lower() == "state" and tokens[3].lower() in {"on", "off"}:
                    state = tokens[3].lower()
                    bond["member_states"][member] = state
                    member_data["enabled"] = state == "on"
                    member_data["_state_explicit"] = True
                    attributes["member_state"] = state
                    bond["review_reasons"].append("bond-member-state")
            elif tokens and tokens[0].lower() == "mode" and len(tokens) >= 2:
                mode = tokens[1].lower()
                bond["settings"]["mode"] = mode
                attributes["bond_mode"] = mode
                index = 2
                while index < len(tokens):
                    key = tokens[index].lower()
                    value = tokens[index + 1] if index + 1 < len(tokens) else True
                    bond["settings"][key] = value
                    index += 2 if value is not True else 1
                bond["review_reasons"].append("bond-mode-not-portable")
            elif tokens:
                key = tokens[0].lower()
                value: Any = tokens[1] if len(tokens) == 2 else tokens[1:] or True
                bond["settings"][key] = value
                attributes["setting"] = key
                attributes["value"] = value
                bond["review_reasons"].append(f"unmodeled-bonding-setting:{key}")
            else:
                bond["review_reasons"].append("malformed-bonding-command")
            inventory_items.append(_logical_inventory_item(
                line, line_num, src_path, "gaia-bonding-group", attributes,
            ))
            continue

        # Bridging groups. Gaia names these interfaces br<ID>.
        m_bridge = re.match(
            r"^(add|set)\s+bridging\s+group\s+(\d+)(?:\s+(.+))?$", line, re.IGNORECASE,
        )
        if m_bridge:
            operation, group_id, remainder = m_bridge.groups()
            bridge = _get_or_create_logical_group(bridging_groups, group_id, "br", "bridge")
            bridge["raw_commands"].append(line)
            tokens = shlex.split(remainder or "")
            attributes: Dict[str, Any] = {"bridging_group_id": int(group_id), "operation": operation.lower()}
            if tokens and tokens[0].lower() in {"interface", "fail-open-interfaces"} and len(tokens) >= 2:
                member_kind, member = tokens[0].lower(), tokens[1]
                if member_kind == "interface":
                    _add_group_member(bridge, member)
                    member_data = _get_or_create_interface(interfaces_dict, member)
                    member_data["source_attributes"].setdefault(
                        "bridging_groups", [],
                    ).append(int(group_id))
                    if len(tokens) >= 4 and tokens[2].lower() == "state" and tokens[3].lower() in {"on", "off"}:
                        state = tokens[3].lower()
                        bridge["member_states"][member] = state
                        member_data["enabled"] = state == "on"
                        member_data["_state_explicit"] = True
                else:
                    bridge.setdefault("fail_open_members", []).append(member)
                attributes["member_interface"] = member
                attributes["member_kind"] = member_kind
            elif tokens:
                key = tokens[0].lower()
                bridge["settings"][key] = tokens[1] if len(tokens) == 2 else tokens[1:] or True
                attributes["setting"] = key
                attributes["value"] = bridge["settings"][key]
                bridge["review_reasons"].append(f"unmodeled-bridging-setting:{key}")
            else:
                bridge["review_reasons"].append("malformed-bridging-command")
            inventory_items.append(_logical_inventory_item(
                line, line_num, src_path, "gaia-bridging-group", attributes,
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
                if_data = _interface_for_command(interfaces_dict, if_name)
                address = f"{ip_str}/{prefix}"
                if address not in if_data["ips"]:
                    if_data["ips"].append(address)
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
                if_data = _interface_for_command(interfaces_dict, if_name)
                address = f"{ip_str}/{prefix}"
                if address not in if_data["ips"]:
                    if_data["ips"].append(address)
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
            if_data = _interface_for_command(interfaces_dict, if_name)
            if_data["enabled"] = (state == "on")
            if_data["_state_explicit"] = True
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
            if_data = _interface_for_command(interfaces_dict, if_name)
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
            if_data = _interface_for_command(interfaces_dict, if_name)
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
            requested_name, ip_str, prefix_raw = m_loopback.groups()
            if requested_name.lower() == "lo":
                explicit_name = next(
                    (name for name, item in interfaces_dict.items()
                     if re.fullmatch(r"loop\d+", name, re.IGNORECASE)
                     and not item.get("_loopback_created")),
                    None,
                )
                if_name = explicit_name or requested_name
            else:
                if_name = requested_name
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                prefix = int(prefix_raw)
                if not 0 <= prefix <= 32:
                    raise ValueError("IPv4 prefix outside 0..32")
                ipaddress.IPv4Address(ip_str)
                if_data = _interface_for_command(interfaces_dict, if_name)
                if_data["interface_type"] = "loopback"
                address = f"{ip_str}/{prefix}"
                if address not in if_data["ips"]:
                    if_data["ips"].append(address)
                if_data["source_attributes"]["raw_creation_command"] = line
                if requested_name.lower() == "lo" and not explicit_name:
                    if_data["_loopback_name_pending"] = True
                    if_data["source_attributes"]["generated_name_unavailable"] = True
                    if_data["review_reasons"].append("loopback-generated-name-not-provided")
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
            if_data = _interface_for_command(interfaces_dict, if_name)
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
        # e.g. set ipv6 static-route default nexthop gateway 2001:db8::1 on
        if re.match(r"^set\s+(?:ipv6\s+)?static-route\s+", line, re.IGNORECASE):
            parsed_route, route_error = _parse_static_route_tokens(line)
            dest_raw = parsed_route.get("destination") if parsed_route else "<unknown>"
            gw_ip = parsed_route.get("next_hop") if parsed_route else None
            family = parsed_route.get("address_family", "ipv4") if parsed_route else "ipv4"
            state = parsed_route.get("state") if parsed_route else None
            default_destination = "::/0" if family == "ipv6" else "0.0.0.0/0"
            dest = default_destination if str(dest_raw).lower() in ("default", default_destination) else dest_raw
            route_key = f"static_{dest}_{gw_ip or (parsed_route or {}).get('interface') or (parsed_route or {}).get('nexthop_type', 'unknown')}"
            route_number = route_name_counts.get(route_key, 0) + 1
            route_name_counts[route_key] = route_number
            route_name = route_key if route_number == 1 else f"{route_key}_{route_number}"
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                if route_error:
                    raise ValueError(route_error)
                if family == "ipv6":
                    dest = ipaddress.IPv6Network(dest, strict=False).with_prefixlen
                else:
                    dest = ipaddress.IPv4Network(dest, strict=False).with_prefixlen
                if gw_ip is not None:
                    if family == "ipv6":
                        ipaddress.IPv6Address(gw_ip)
                    else:
                        ipaddress.IPv4Address(gw_ip)
                unmodeled = parsed_route.get("unmodeled", {})
                for monitor in unmodeled.get("monitored-ip", []):
                    if family == "ipv6":
                        ipaddress.IPv6Address(monitor["address"])
                    else:
                        ipaddress.IPv4Address(monitor["address"])
                unsupported_settings = {
                    key: value for key, value in unmodeled.items() if key not in {"comment", "comments"}
                }
                nexthop_type = parsed_route.get("nexthop_type")
                comment = parsed_route.get("comment")
                if nexthop_type in {"blackhole", "reject", "rank"}:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    notes.extend([f"unmodeled-route-setting:{key}" for key in unsupported_settings])
                    notes.append(f"unmodeled-route-nexthop:{nexthop_type}")
                elif unsupported_settings or parsed_route.get("legacy_syntax"):
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    notes.extend([f"unmodeled-route-setting:{key}" for key in unsupported_settings])
                elif state is None:
                    status = ExtractionStatus.EXTRACT_ONLY
                    notes.append("missing-static-route-state")
                elif state == "on" and nexthop_type in {"gateway", "interface"}:
                    routes.append(IRRoute(
                        name=route_name, destination=dest, next_hop=gw_ip,
                        interface=parsed_route.get("interface"), priority=parsed_route.get("priority"),
                        address_family=family, enabled=True, description=comment,
                        source_attributes={"raw_command": line, **({"comment": comment} if comment is not None else {})},
                    ))
                else:
                    status = ExtractionStatus.EXTRACT_ONLY
                    notes.append("disabled-static-route" if state == "off" else "missing-static-route-nexthop")
            except ValueError as exc:
                status = ExtractionStatus.PARSE_ERROR
                notes.append(f"invalid-static-route:{exc}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/routing",
                name=route_name,
                source_type="gaia-static-route",
                source_attributes=parsed_route or {"raw_command": line},
                status=status, requires_manual_review=(status in {ExtractionStatus.PARSE_ERROR, ExtractionStatus.PARTIALLY_NORMALIZED}), notes=notes,
            ))
            continue

        m_dns = re.match(r"^set\s+dns\s+([^\s]+)\s+(.+)$", line, re.IGNORECASE)
        if m_dns:
            setting, value = m_dns.groups()
            setting_key = setting.lower()
            status = ExtractionStatus.NORMALIZED if setting_key in {
                "primary", "secondary", "tertiary", "domain", "domain-name", "search", "search-suffix",
            } else ExtractionStatus.EXTRACT_ONLY
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/dns", name=f"dns_{setting}",
                source_type="gaia-dns", source_attributes={"setting": setting_key, "value": value},
                status=status,
                notes=[] if status == ExtractionStatus.NORMALIZED else ["unmodeled-gaia-dns-setting"],
            ))
            continue

        m_domain = re.match(r"^set\s+domain(?:-name|name)\s+(.+)$", line, re.IGNORECASE)
        if m_domain:
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/system", name="domain-name",
                source_type="gaia-domain-name", source_attributes={"value": m_domain.group(1)},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        m_ntp = re.match(r"^(set|add)\s+ntp\s+(.+)$", line, re.IGNORECASE)
        if m_ntp:
            tokens = shlex.split(m_ntp.group(2))
            setting = tokens[0].lower() if tokens else ""
            attrs: Dict[str, Any] = {"setting": setting, "values": tokens[1:], "raw_command": line}
            if setting == "server" and len(tokens) >= 3:
                attrs.update({"role": tokens[1].lower(), "address": tokens[2], "options": tokens[3:]})
            elif setting in {"active", "enable", "enabled"} and len(tokens) >= 2:
                attrs["enabled"] = tokens[1].lower() == "on"
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/ntp", name=f"ntp_{setting or 'setting'}",
                source_type="gaia-ntp", source_attributes=attrs,
                status=ExtractionStatus.NORMALIZED if setting in {"server", "active", "enable", "enabled"} else ExtractionStatus.EXTRACT_ONLY,
            ))
            continue

        m_snmp = re.match(r"^(set|add)\s+snmp\s+(.+)$", line, re.IGNORECASE)
        if m_snmp:
            tokens = shlex.split(m_snmp.group(2))
            setting = tokens[0].lower() if tokens else "setting"
            attrs: Dict[str, Any] = {"setting": setting, "raw_command": sanitize_raw_text(line)}
            if setting == "community" and len(tokens) >= 2:
                attrs["community"] = tokens[1]
                attrs["options"] = tokens[2:]
            else:
                attrs["values"] = tokens[1:]
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/snmp", name=f"snmp_{setting}",
                source_type="gaia-snmp", source_attributes=sanitize_source_attributes(attrs),
                status=ExtractionStatus.EXTRACT_ONLY,
                notes=["SNMP retained as structured inventory; no canonical IR model"],
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

    for group in bonding_groups.values():
        for member in group["members"]:
            member_data = interfaces_dict.get(member, {})
            if member_data.get("_state_explicit"):
                group["member_states"].setdefault(member, "on" if member_data.get("enabled") else "off")
        data = _get_or_create_interface(interfaces_dict, group["name"])
        data["interface_type"] = "aggregate"
        data["members"] = list(group["members"])
        attributes = data["source_attributes"]
        attributes.update({
            "bonding_group_id": group["id"],
            "bond_members": list(group["members"]),
            "bond_settings": dict(group["settings"]),
            "bond_member_states": dict(group["member_states"]),
            "bond_raw_commands": list(group["raw_commands"]),
        })
        if "mode" in group["settings"]:
            attributes["bond_mode"] = group["settings"]["mode"]
        for key in ("primary", "xmit-hash-policy", "lacp-rate", "up-delay", "down-delay", "mii-interval"):
            if key in group["settings"]:
                attributes[f"bond_{key.replace('-', '_')}"] = group["settings"][key]
        attributes["bond_monitoring"] = {
            key: value for key, value in group["settings"].items()
            if key in {"monitoring", "monitoring-type", "mii-interval", "arp-target", "arp-target-ip"}
        }
        data["review_reasons"] = list(dict.fromkeys(
            group["review_reasons"] + (["bond-behavior-not-portable"] if group["settings"] else []),
        ))
        if group["settings"] or group["member_states"]:
            data["migration_status"] = "PARTIALLY_NORMALIZED"

    for group in bridging_groups.values():
        for member in group["members"]:
            member_data = interfaces_dict.get(member, {})
            if member_data.get("_state_explicit"):
                group["member_states"].setdefault(member, "on" if member_data.get("enabled") else "off")
        data = _get_or_create_interface(interfaces_dict, group["name"])
        data["interface_type"] = "bridge"
        attributes = data["source_attributes"]
        attributes.update({
            "bridging_group_id": group["id"],
            "bridge_members": list(group["members"]),
            "bridge_member_states": dict(group["member_states"]),
            "bridge_settings": dict(group["settings"]),
            "bridge_raw_commands": list(group["raw_commands"]),
        })
        if group.get("fail_open_members"):
            attributes["bridge_fail_open_members"] = list(group["fail_open_members"])
        data["review_reasons"] = list(dict.fromkeys(
            group["review_reasons"] + ["bridge-behavior-not-portable"],
        ))
        data["migration_status"] = "PARTIALLY_NORMALIZED"

    ir_interfaces: List[IRInterface] = []
    for if_name, data in interfaces_dict.items():
        ips = data.get("ips", [])
        ips = [ip for ip in ips if ":" not in ip] + [ip for ip in ips if ":" in ip]
        ir_interfaces.append(IRInterface(
            name=if_name,
            status=data.get("enabled", True),
            ip=ips[0] if ips else None,
            secondary_ips=[IRInterfaceSecondaryIP(ip=ip) for ip in ips[1:]],
            zone=data.get("zone"),
            description=data.get("description"),
            parent=data.get("parent"), vlanid=data.get("vlanid"),
            interface_type=data.get("interface_type") or ("vlan" if data.get("vlanid") else "physical"),
            members=list(data.get("members", [])),
            requires_manual_review=bool(data.get("review_reasons")),
            migration_status=data.get("migration_status", "NORMALIZED"),
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
        source_context=gateway or cluster_member or domain or source_response,
    )

    source_context = (
        f"{domain or 'global'}:{gateway or cluster_member or 'unknown'}:{source_response}"
        if source_response else gateway or cluster_member or domain or "gaia"
    )
    provenance = {
        "domain": domain,
        "gateway": gateway,
        "source_response": source_response,
        "cluster_member": cluster_member,
    }
    for item in inventory_items:
        item.domain = domain or item.domain
        item.source_context = source_context
        item.source_attributes.setdefault("provenance", provenance)
    for item in ir_interfaces:
        item.source_context = source_context
        item.source_attributes.setdefault("provenance", provenance)
    for item in ir_zones:
        item.source_context = source_context
        item.source_attributes.setdefault("provenance", provenance)
    for item in routes:
        item.source_attributes.setdefault("provenance", provenance)

    return metadata, ir_interfaces, ir_zones, routes, inventory_items, unsupported_items
