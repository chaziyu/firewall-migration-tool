"""Check Point Gaia OS CLI and system configuration parser."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.ir.core import (
    IRConfig,
    IRInterface,
    IRInterfaceIPv6Address,
    IRInterfaceSecondaryIP,
    IRMetadata,
    IRRoute,
    IRZone,
)
from fwmigrate.parsers.checkpoint.performance import is_performance_command


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _parse_bounded_int(raw: str, minimum: int, maximum: int) -> tuple[int | str, bool]:
    try:
        value = int(raw)
    except ValueError:
        return raw, False
    return value, minimum <= value <= maximum


def _parse_management_access_line(
    line: str, line_num: int, source_path: str,
) -> Optional[SourceInventoryItem]:
    """Parse documented persistent Gaia administrative commands only."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    lowered = [token.lower() for token in tokens]
    if len(tokens) < 3:
        return None

    attrs: Dict[str, Any] = {"raw_command": sanitize_raw_text(line)}
    service: Optional[str] = None
    key: Optional[str] = None
    status = ExtractionStatus.NORMALIZED
    notes: List[str] = []

    if lowered[:3] == ["set", "web", "daemon-enable"] and len(tokens) == 4:
        service, key = "web", "enabled"
        attrs[key] = {"on": True, "off": False}.get(lowered[3])
    elif lowered[:3] == ["set", "web", "ssl-port"] and len(tokens) == 4:
        service, key = "web", "ssl_port"
        attrs[key], valid = _parse_bounded_int(tokens[3], 1, 65535)
        if not valid: status = ExtractionStatus.PARSE_ERROR
    elif lowered[:3] == ["set", "web", "session-timeout"] and len(tokens) == 4:
        service, key = "web", "session_timeout"
        attrs[key], valid = _parse_bounded_int(tokens[3], 1, 720)
        if not valid: status = ExtractionStatus.PARSE_ERROR
    elif lowered[:3] == ["set", "web", "ssl3-enabled"] and len(tokens) == 4:
        service, key = "web", "ssl3_enabled"
        attrs[key] = {"on": True, "off": False}.get(lowered[3])
    elif lowered[:3] == ["set", "web", "table-refresh-rate"] and len(tokens) == 4:
        service, key = "web", "table_refresh_rate"
        attrs[key], valid = _parse_bounded_int(tokens[3], 10, 240)
        if not valid: status = ExtractionStatus.PARSE_ERROR
    elif lowered[:3] == ["set", "management", "interface"] and len(tokens) == 4:
        service, key, attrs["interface"] = "management-interface", "interface", tokens[3]
    elif lowered[:2] == ["set", "ssh"] and len(tokens) == 4 and lowered[2] in {"daemon-enable", "enabled"}:
        service, key = "ssh", "enabled"
        attrs[key] = {"on": True, "off": False}.get(lowered[3])
    elif lowered[:3] == ["set", "ssh", "port"] and len(tokens) == 4:
        service, key = "ssh", "port"
        try: attrs[key] = int(tokens[3])
        except ValueError: attrs[key] = tokens[3]; status = ExtractionStatus.PARSE_ERROR
    elif lowered[:2] in (["add", "allowed-client"], ["delete", "allowed-client"], ["show", "allowed-client"]):
        service = "management-clients"
        operation = lowered[0]
        if len(tokens) not in {5, 7} or lowered[2] not in {"host", "network"}:
            attrs.update({"operation": operation, "raw_tokens": tokens[2:]})
            status = ExtractionStatus.PARSE_ERROR
            notes.append("unrecognized-allowed-client-syntax")
        else:
            client_type, family_token, address = tokens[2], lowered[3], tokens[4]
            expected_family = {"ipv4-address": 4, "ipv6-address": 6}.get(family_token)
            prefix = None
            if client_type == "host":
                if len(tokens) != 5:
                    expected_family = None
            elif client_type == "network" and len(tokens) == 7 and lowered[5] == "mask-length":
                try:
                    prefix = int(tokens[6])
                except ValueError:
                    pass
            else:
                expected_family = None
            try:
                parsed = ipaddress.ip_address(address)
                if expected_family != parsed.version or (client_type == "network" and prefix is None):
                    raise ValueError("invalid allowed-client address form")
                if client_type == "network" and not 0 <= prefix <= parsed.max_prefixlen:
                    raise ValueError("allowed-client prefix outside address-family range")
            except ValueError:
                status = ExtractionStatus.PARSE_ERROR
                notes.append("invalid-allowed-client-address")
            attrs.update({"operation": operation, "client_type": client_type, "address": address,
                          "address_family": f"ipv{expected_family}" if expected_family else None})
            if prefix is not None:
                attrs.update({"prefix": prefix, "mask_length": prefix})
    elif lowered[:3] in (["set", "rba", "user"], ["add", "rba", "user"]):
        service = "rbac-role"
        if len(tokens) < 4:
            status = ExtractionStatus.PARSE_ERROR
            notes.append("malformed-rba-user-command")
        else:
            attrs["username"] = tokens[3]
            if len(tokens) != 6 or lowered[4] not in {"roles", "access-mechanisms"}:
                status = ExtractionStatus.PARSE_ERROR
                notes.append("malformed-rba-user-command")
            else:
                values = tokens[5].split(",")
                if not all(values):
                    status = ExtractionStatus.PARSE_ERROR
                    notes.append("malformed-rba-user-values")
                elif lowered[4] == "roles":
                    attrs["roles"] = values
                else:
                    attrs["access_mechanisms"] = values
    elif lowered[:3] in (["set", "web", "server"], ["set", "web", "ssl-server"]):
        service, status = "web", ExtractionStatus.PARTIALLY_NORMALIZED
        notes.append("legacy-synthetic-gaia-management-access-syntax")
    elif lowered[:3] == ["set", "ssh", "server"]:
        service, status = "ssh", ExtractionStatus.PARTIALLY_NORMALIZED
        notes.append("legacy-synthetic-gaia-management-access-syntax")
    elif len(tokens) >= 5 and lowered[:2] == ["set", "interface"] and lowered[3] == "permitted-ip":
        service, status = "management-clients", ExtractionStatus.PARTIALLY_NORMALIZED
        attrs.update({"interface": tokens[2], "client": tokens[4]})
        notes.append("legacy-synthetic-gaia-management-access-syntax")
    else:
        return None

    if attrs.get("enabled") is None and key in {"enabled", "ssl3_enabled"}:
        status = ExtractionStatus.PARSE_ERROR
    attrs["service"] = f"gaia-{service}"
    return SourceInventoryItem(
        domain="gaia", source_path=f"{source_path}/management-access", name=f"{service}_{line_num}",
        source_type=f"gaia-{service}", source_attributes=sanitize_source_attributes(attrs),
        status=status, requires_manual_review=status != ExtractionStatus.NORMALIZED,
        notes=notes,
    )


class GaiaDHCPReservation(BaseModel):
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class GaiaDHCPServer(BaseModel):
    subnet: str
    netmask: Optional[str] = None
    enabled: bool = True
    interface: Optional[str] = None
    pool_ranges: List[Dict[str, Any]] = Field(default_factory=list)
    default_gateway: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    domain: Optional[str] = None
    lease_time_seconds: Optional[int] = None
    max_lease_seconds: Optional[int] = None
    reservations: List[GaiaDHCPReservation] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class GaiaPBRRule(BaseModel):
    priority: int
    order: int
    action: Optional[str] = None
    routing_table: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    incoming_interface: Optional[str] = None
    enabled: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


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
                if not 1 <= priority <= 8:
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
    dhcp_servers: Dict[str, GaiaDHCPServer] = {}
    dhcp_process_enabled = True
    pbr_tables: List[Dict[str, Any]] = []
    pbr_rules: Dict[int, GaiaPBRRule] = {}
    pbr_order = 0

    lines = gaia_text.splitlines()

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if is_performance_command(line):
            continue

        src_path = "gaia/show-configuration"

        management_item = _parse_management_access_line(line, line_num, src_path)
        if management_item:
            inventory_items.append(management_item)
            continue

        # Gaia DHCP server commands (R81 clish). These are separate from
        # interface DHCP client mode and only consume persistent add/set lines.
        m_dhcp = re.match(r"^(add|set)\s+dhcp\s+server(?:\s+(.+))?$", line, re.IGNORECASE)
        if m_dhcp:
            operation, remainder = m_dhcp.groups()
            tokens = shlex.split(remainder or "")
            if tokens and tokens[0].lower() in {"enable", "disable"}:
                dhcp_process_enabled = tokens[0].lower() == "enable"
                inventory_items.append(SourceInventoryItem(
                    domain="gaia", source_path=f"{src_path}/dhcp-server", name="process",
                    source_type="gaia-dhcp-server", source_attributes={
                        "enabled": dhcp_process_enabled, "raw_command": line,
                    }, status=ExtractionStatus.NORMALIZED,
                ))
                continue
            if len(tokens) >= 2 and tokens[0].lower() == "subnet":
                subnet = tokens[1]
                server = dhcp_servers.setdefault(subnet, GaiaDHCPServer(subnet=subnet))
                index = 2
                while index < len(tokens):
                    key = tokens[index].lower()
                    if key in {"enable", "disable"}:
                        server.enabled = key == "enable"
                        index += 1
                    elif key == "netmask" and index + 1 < len(tokens):
                        server.netmask = tokens[index + 1]; index += 2
                    elif key in {"default-lease", "max-lease"} and index + 1 < len(tokens):
                        try:
                            value = int(tokens[index + 1])
                            if key == "default-lease": server.lease_time_seconds = value
                            else: server.max_lease_seconds = value
                        except ValueError:
                            server.source_attributes.setdefault("invalid", {})[key] = tokens[index + 1]
                        index += 2
                    elif key in {"default-gateway", "domain", "interface"} and index + 1 < len(tokens):
                        value = tokens[index + 1]
                        setattr(server, {"default-gateway": "default_gateway"}.get(key, key), value)
                        index += 2
                    elif key == "dns" and index + 1 < len(tokens):
                        server.dns_servers.extend(x.strip() for x in " ".join(tokens[index + 1:]).split(",") if x.strip())
                        index = len(tokens)
                    elif key in {"include-ip-pool", "exclude-ip-pool"}:
                        pool_kind = "include" if key.startswith("include") else "exclude"
                        if index + 3 < len(tokens) and tokens[index + 1].lower() == "start":
                            pool = {"type": pool_kind, "start": tokens[index + 2], "end": tokens[index + 4] if index + 4 < len(tokens) and tokens[index + 3].lower() == "end" else None, "enabled": True}
                            index += 5 if pool["end"] else 2
                        else:
                            value = tokens[index + 1]
                            state = tokens[index + 2] if index + 2 < len(tokens) else "enable"
                            start, _, end = value.partition("-")
                            pool = {"type": pool_kind, "start": start, "end": end or None, "enabled": state.lower() == "enable"}
                            index += 3 if index + 2 < len(tokens) else 2
                        server.pool_ranges.append(pool)
                    elif key == "reservation":
                        # Not part of the documented R81 clish syntax; retain
                        # an explicit persistent command without fabricating it.
                        values = tokens[index + 1:]
                        ip_value = next((value for value in values if _is_ipv4(value)), None)
                        mac_value = next((value for value in values if re.fullmatch(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}", value)), None)
                        server.reservations.append(GaiaDHCPReservation(
                            ip_address=ip_value, mac_address=mac_value,
                            source_attributes={"raw_tokens": values},
                        ))
                        index = len(tokens)
                    else:
                        server.source_attributes.setdefault("advanced_options", []).append(tokens[index:])
                        index = len(tokens)
                server.source_attributes["raw_commands"] = server.source_attributes.get("raw_commands", []) + [line]
                continue

        # R81 Advanced Routing PBR commands are deliberately not static routes.
        m_pbr = re.match(r"^set\s+pbr\s+(.+)$", line, re.IGNORECASE)
        if m_pbr:
            tokens = shlex.split(m_pbr.group(1))
            if len(tokens) >= 3 and tokens[0].lower() == "table":
                table_attrs: Dict[str, Any] = {
                    "table": tokens[1], "tokens": tokens[2:], "raw_command": line,
                    "order": len(pbr_tables) + 1,
                }
                if len(tokens) >= 4 and tokens[2].lower() == "static-route":
                    table_attrs["destination"] = tokens[3]
                    table_attrs["enabled"] = "off" not in [token.lower() for token in tokens]
                    try:
                        lowered = [token.lower() for token in tokens]
                        hop = lowered.index("nexthop", 4)
                        if tokens[hop + 1].lower() == "gateway":
                            kind = tokens[hop + 2].lower()
                            if kind == "address": table_attrs["next_hop"] = tokens[hop + 3]
                            elif kind == "logical": table_attrs["outgoing_interface"] = tokens[hop + 3]
                        if "priority" in lowered[hop:]: table_attrs["priority"] = int(tokens[lowered.index("priority", hop) + 1])
                    except (ValueError, IndexError):
                        table_attrs["parse_error"] = "malformed-pbr-table-next-hop"
                pbr_tables.append(table_attrs)
                inventory_items.append(SourceInventoryItem(
                    domain="gaia", source_path=f"{src_path}/pbr/tables", name=tokens[1],
                    source_type="gaia-pbr-table", source_attributes=table_attrs,
                    status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
                    notes=["PBR preserved as structured source inventory; not mapped to static routes"],
                ))
                continue
            if len(tokens) >= 3 and tokens[0].lower() == "rule" and tokens[1].lower() == "priority":
                try: priority = int(tokens[2])
                except ValueError: priority = -1
                if priority > 0:
                    rule = pbr_rules.setdefault(priority, GaiaPBRRule(priority=priority, order=pbr_order + 1))
                    pbr_order = max(pbr_order, rule.order)
                    tail = tokens[3:]
                    if tail and tail[0].lower() == "off": rule.enabled = False
                    for pos, token in enumerate(tail):
                        value = tail[pos + 1] if pos + 1 < len(tail) else None
                        if token.lower() == "action":
                            rule.action = value
                            if value and value.lower() == "table" and pos + 2 < len(tail): rule.routing_table = tail[pos + 2]
                        elif token.lower() == "from": rule.source = value
                        elif token.lower() == "to": rule.destination = value
                        elif token.lower() == "interface": rule.incoming_interface = value
                        elif token.lower() == "port": rule.service = value
                        elif token.lower() == "protocol": rule.protocol = value
                    rule.source_attributes.setdefault("raw_commands", []).append(line)
                    continue

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
            r"^set\s+interface\s+([^\s]+)\s+(mtu|link-speed|speed|duplex|auto-negotiation|mac-addr|mac-address|ipv6-autoconfig|monitor-mode|rx-ringsize|tx-ringsize)\s+(.+)$",
            line, re.IGNORECASE,
        )
        if m_if_behavior:
            if_name, setting, value = m_if_behavior.groups()
            setting = setting.lower()
            if_data = _interface_for_command(interfaces_dict, if_name)
            if setting in {"rx-ringsize", "tx-ringsize"}:
                try:
                    ring_size = int(value)
                    if not 0 <= ring_size <= 4096:
                        raise ValueError("ring size outside 0..4096")
                except ValueError as exc:
                    inventory_items.append(SourceInventoryItem(
                        domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                        name=f"{if_name}_{setting}", source_type="gaia-interface-ring-size",
                        source_attributes={"interface": if_name, "setting": setting, "value": value},
                        status=ExtractionStatus.PARSE_ERROR, requires_manual_review=True,
                        notes=[f"invalid-interface-ring-size:{exc}"],
                    ))
                    continue
                if_data["source_attributes"][setting] = ring_size
                reason = f"platform-specific-interface-setting:{setting}"
                if_data["review_reasons"].append(reason)
                if_data["migration_status"] = "PARTIALLY_NORMALIZED"
                inventory_items.append(SourceInventoryItem(
                    domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                    name=f"{if_name}_{setting}", source_type="gaia-interface-ring-size",
                    source_attributes={"interface": if_name, "setting": setting, "value": ring_size},
                    status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
                    notes=[reason],
                ))
                continue
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
                "primary", "secondary", "tertiary", "domain", "domain-name", "suffix", "search", "search-suffix",
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

    for server in dhcp_servers.values():
        server.enabled = server.enabled and dhcp_process_enabled
        attrs = server.model_dump()
        attrs["process_enabled"] = dhcp_process_enabled
        notes = []
        if server.source_attributes.get("advanced_options"):
            notes.append("unmodeled-gaia-dhcp-options")
        if server.source_attributes.get("reservations"):
            notes.append("gaia-dhcp-reservation-syntax-not-documented-in-r81-clish")
        inventory_items.append(SourceInventoryItem(
            domain="gaia", source_path=f"{src_path}/dhcp-server/subnet", name=server.subnet,
            source_type="gaia-dhcp-server", source_attributes=attrs,
            status=ExtractionStatus.PARTIALLY_NORMALIZED if notes else ExtractionStatus.NORMALIZED,
            requires_manual_review=bool(notes), notes=notes,
        ))
    for rule in pbr_rules.values():
        rule_attrs = rule.model_dump()
        rule_attrs.update({
            "rule_id": rule.priority, "rule_order": rule.order,
            "routing_table_reference": rule.routing_table,
        })
        inventory_items.append(SourceInventoryItem(
            domain="gaia", source_path=f"{src_path}/pbr/rules", name=f"priority-{rule.priority}",
            source_type="gaia-pbr-rule", source_attributes=rule_attrs,
            status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
            notes=["PBR preserved as structured source inventory; no suitable portable IR model"],
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
        ipv4_ips = [ip for ip in ips if ":" not in ip]
        ipv6_ips = [ip for ip in ips if ":" in ip]
        ir_interfaces.append(IRInterface(
            name=if_name,
            status=data.get("enabled", True),
            ip=ipv4_ips[0] if ipv4_ips else None,
            secondary_ips=[IRInterfaceSecondaryIP(ip=ip) for ip in ipv4_ips[1:]],
            ipv6_address=ipv6_ips[0] if ipv6_ips else None,
            source_ipv6_address=ipv6_ips[0] if ipv6_ips else None,
            additional_ipv6_addresses=[
                IRInterfaceIPv6Address(address=ip, source_address=ip) for ip in ipv6_ips[1:]
            ],
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
