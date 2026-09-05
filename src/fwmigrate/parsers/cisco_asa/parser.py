from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Tuple

from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRInterface,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRSchedule,
    IRService,
    IRServiceGroup,
    IRServicePort,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, PolicyAction, ServiceProtocol
from fwmigrate.parsers.cisco_asa.acl_parser import KNOWN_PROTOCOLS, parse_acl_binding, parse_acl_line
from fwmigrate.parsers.cisco_asa.model import (
    CiscoASAConfig,
    CiscoAccessRule,
    CiscoDiagnostic,
    CiscoInterface,
    CiscoIPv6Address,
    CiscoNamedGroup,
    CiscoNATRule,
    CiscoRouteMap,
    CiscoRouteMapRule,
    CiscoNetworkGroup,
    CiscoNetworkObject,
    CiscoNetworkServiceObject,
    CiscoPortSpec,
    CiscoServiceGroup,
    CiscoServiceObject,
    CiscoServicePort,
    CiscoStaticRoute,
    CiscoTimeRange,
    CiscoTimeRangeClause,
)
from fwmigrate.parsers.cisco_asa.net_utils import normalize_ipv4_network, parse_ipv4_netmask
from fwmigrate.parsers.cisco_asa.service_parser import parse_service_clause


def mask_to_cidr(mask: str) -> Optional[int]:
    """Backward-compatible strict mask helper. Invalid masks return ``None``."""
    return parse_ipv4_netmask(mask)


def _safe_name(prefix: str, expression: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]+", "_", expression).strip("_").lower()
    clean = clean[:48] or "value"
    digest = hashlib.sha1(expression.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}_{clean}_{digest}"


class CiscoASAParser:
    """Deterministic offline parser for Cisco ASA running configuration."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoASAConfig()
        self._nat_section_counts: Dict[str, int] = {}

    def _record_unsupported(self, line_number: int, line: str, reason: str) -> None:
        self.config.unsupported_commands.append(
            {"line_number": line_number, "raw_line": line, "reason": reason}
        )

    def _record_diagnostic(
        self, line_number: int, line: str, reason: str, section: str,
        object_name: Optional[str] = None, migration_effect: str = "PARSE_ERROR",
    ) -> None:
        diagnostic = CiscoDiagnostic(
            line_number=line_number, section=section, object_name=object_name,
            raw_line=line, reason=reason, migration_effect=migration_effect,
            severity="error" if migration_effect == "PARSE_ERROR" else "warning",
        )
        self.config.diagnostics.append(diagnostic)
        if migration_effect == "PARSE_ERROR":
            self.config.parse_errors.append(diagnostic.model_dump())

    def _record_acl_consumer(self, acl_name: str, consumer_type: str, line_number: int, line: str) -> None:
        self.config.acl_consumers.setdefault(acl_name, []).append({
            "consumer_type": consumer_type, "line_number": line_number, "raw_line": line,
        })

    def _parse_network_object(self, name: str, block: List[str]) -> CiscoNetworkObject:
        obj = CiscoNetworkObject(name=name, raw_lines=list(block))
        for sub in block:
            parts = sub.split()
            lower = sub.lower()
            if lower.startswith("host ") and len(parts) >= 2:
                try:
                    address = ipaddress.ip_address(parts[1])
                    obj.type, obj.value = "host", str(address)
                    obj.address_family = f"ipv{address.version}"
                except ValueError:
                    obj.source_attributes["invalid_host"] = parts[1]
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
            elif lower.startswith("subnet ") and len(parts) >= 2:
                value = None
                if ":" in parts[1] and "/" in parts[1]:
                    try:
                        value = str(ipaddress.IPv6Network(parts[1], strict=False))
                        obj.address_family = "ipv6"
                    except ValueError:
                        value = None
                elif len(parts) >= 3:
                    value = normalize_ipv4_network(parts[1], parts[2])
                    obj.address_family = "ipv4" if value else None
                if value is None:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_subnet"] = " ".join(parts[1:])
                else:
                    obj.type, obj.value = "subnet", value
            elif lower.startswith("range ") and len(parts) >= 3:
                try:
                    start, end = ipaddress.ip_address(parts[1]), ipaddress.ip_address(parts[2])
                    if start.version != end.version or int(start) > int(end):
                        raise ValueError
                    obj.type, obj.value = "range", f"{start}-{end}"
                    obj.address_family = f"ipv{start.version}"
                except ValueError:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_range"] = " ".join(parts[1:3])
            elif lower.startswith("fqdn "):
                values = parts[1:]
                if values and values[0].lower() in {"v4", "v6"}:
                    family = values.pop(0).lower()
                    obj.address_family = "ipv4" if family == "v4" else "ipv6"
                    obj.source_attributes["address_family"] = obj.address_family
                if values:
                    obj.type, obj.value = "fqdn", " ".join(values)
            elif lower.startswith("description "):
                obj.description = sub.split(maxsplit=1)[1]
            elif lower.startswith("nat "):
                obj.nat_lines.append(sub)
            else:
                obj.source_attributes.setdefault("unmodeled_lines", []).append(sub)
        if obj.type is None or obj.value is None:
            obj.migration_status = "PARSE_ERROR"
            obj.requires_manual_review = True
        elif obj.source_attributes.get("unmodeled_lines"):
            obj.migration_status = "PARTIALLY_NORMALIZED"
            obj.requires_manual_review = True
        return obj

    def parse_raw(self) -> CiscoASAConfig:
        self.config = CiscoASAConfig()
        self._nat_section_counts = {}
        lines = [line.rstrip() for line in self.raw_lines]
        remarks: Dict[str, List[str]] = {}
        i = 0
        while i < len(lines):
            raw = lines[i]
            line = raw.strip()
            line_number = i + 1
            if not line or line.startswith((":", "!")):
                i += 1
                continue
            if line.lower().startswith("hostname "):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    self.config.hostname = parts[1]
                i += 1
                continue

            match = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
            if match:
                interface = CiscoInterface(name=match.group(1))
                interface_name = interface.name
                if re.match(r"^Port-channel(\d+)$", interface_name, re.IGNORECASE):
                    interface.interface_type = "port-channel"
                    interface.port_channel_id = int(re.search(r"(\d+)$", interface_name).group(1))
                elif re.match(r"^BVI(\d+)$", interface_name, re.IGNORECASE):
                    interface.interface_type = "bvi"
                    interface.bvi_id = int(re.search(r"(\d+)$", interface_name).group(1))
                elif re.match(r"^Redundant(\d+)$", interface_name, re.IGNORECASE):
                    interface.interface_type = "redundant"
                elif re.match(r"^\S+\.\d+$", interface_name):
                    interface.interface_type = "subinterface"
                    interface.parent_interface, _, vlan = interface_name.rpartition(".")
                    interface.vlan_id = int(vlan)
                else:
                    interface.interface_type = "physical"
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    interface.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("nameif "):
                        if interface.nameif is not None:
                            interface.source_attributes.setdefault("nameif_history", []).append(interface.nameif)
                        interface.nameif = sub.split(maxsplit=1)[1]
                    elif lower == "no nameif":
                        interface.nameif = None
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    elif lower.startswith("security-level "):
                        if interface.security_level is not None:
                            interface.source_attributes.setdefault("security_level_history", []).append(interface.security_level)
                        try:
                            interface.security_level = int(parts[1])
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                    elif lower == "no security-level":
                        interface.security_level = None
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    elif lower.startswith("vlan "):
                        try:
                            interface.vlan_id = int(parts[1])
                            interface.interface_type = "subinterface"
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith("channel-group "):
                        try:
                            interface.channel_group = int(parts[1])
                            interface.channel_group_mode = parts[3] if len(parts) >= 4 and parts[2].lower() == "mode" else None
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith("member-interface "):
                        interface.redundant_interface_members.append(parts[1])
                        interface.interface_type = "redundant"
                    elif lower.startswith("bridge-group "):
                        try:
                            interface.bridge_group = int(parts[1])
                            if interface.interface_type == "physical":
                                interface.interface_type = "bridge-member"
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith("mtu "):
                        try:
                            if interface.mtu is not None:
                                interface.source_attributes.setdefault("mtu_history", []).append(interface.mtu)
                            interface.mtu = int(parts[1])
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith(("routing-context ", "vrf forwarding ")):
                        _, value = sub.split(maxsplit=1)
                        if lower.startswith("vrf forwarding "):
                            interface.vrf = value
                        else:
                            interface.routing_context = value
                    elif lower.startswith("ip address "):
                        interface.source_attributes.setdefault("ip_address_history", []).append(sub)
                        if len(parts) >= 3 and parts[2].lower() == "dhcp":
                            interface.ip_mode = "dhcp"
                            interface.dhcp_setroute = "setroute" in {p.lower() for p in parts[3:]}
                            interface.source_attributes["ip_address"] = " ".join(parts[2:])
                        elif len(parts) >= 4:
                            interface.ip_mode, interface.ip, interface.mask = "static", parts[2], parts[3]
                            if len(parts) >= 6 and parts[4].lower() == "standby":
                                interface.standby_ip = parts[5]
                            elif len(parts) > 4:
                                interface.source_attributes.setdefault("unmodeled_ip_address_tokens", []).extend(parts[4:])
                    elif lower.startswith("ipv6 address "):
                        args = parts[2:]
                        if args and args[0].lower() == "autoconfig":
                            interface.ipv6_autoconfig = True
                        elif args and args[0].lower() == "dhcp":
                            interface.ipv6_dhcp = True
                            interface.ipv6_dhcp_setroute = "setroute" in {p.lower() for p in args[1:]}
                        elif args:
                            try:
                                address = str(ipaddress.IPv6Interface(args[0]))
                                standby = None
                                eui64 = "eui-64" in {p.lower() for p in args[1:]}
                                link_local = "link-local" in {p.lower() for p in args[1:]}
                                if "standby" in {p.lower() for p in args[1:]}:
                                    pos = [p.lower() for p in args].index("standby")
                                    standby = str(ipaddress.IPv6Address(args[pos + 1])) if pos + 1 < len(args) else None
                                interface.ipv6_addresses.append(CiscoIPv6Address(
                                    address=address, standby=standby, eui64=eui64,
                                    link_local=link_local, raw=sub,
                                ))
                            except (ValueError, IndexError):
                                interface.migration_status = "PARSE_ERROR"
                                interface.requires_manual_review = True
                                interface.source_attributes.setdefault("invalid_ipv6_addresses", []).append(sub)
                    elif lower == "management-only":
                        interface.management_only = True
                    elif lower.startswith("description "):
                        interface.description = sub.split(maxsplit=1)[1]
                    elif lower.startswith("policy-route route-map "):
                        parts = sub.split()
                        if len(parts) == 3:
                            interface.policy_route_maps.append(parts[2])
                        else:
                            interface.source_attributes.setdefault("invalid_routing_settings", []).append(sub)
                    elif lower == "shutdown":
                        interface.shutdown = True
                        interface.administrative_state = "down"
                    elif lower == "no shutdown":
                        interface.shutdown = False
                        interface.administrative_state = "up"
                    elif lower == "no ip address":
                        interface.ip = interface.mask = interface.ip_mode = interface.standby_ip = None
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    else:
                        interface.source_attributes.setdefault("unmodeled_lines", []).append(sub)
                    i += 1
                if interface.ip_mode == "static" and normalize_ipv4_network(interface.ip or "", interface.mask or "") is None:
                    interface.migration_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.source_attributes["invalid_ip_address"] = f"{interface.ip or ''} {interface.mask or ''}".strip()
                    self._record_diagnostic(line_number, line, "Invalid interface IPv4 address/netmask", "interface", interface.name)
                elif interface.source_attributes.get("unmodeled_lines"):
                    interface.requires_manual_review = True
                    interface.migration_status = "PARTIALLY_NORMALIZED"
                if interface.dhcp_setroute or interface.ipv6_dhcp_setroute or interface.management_only or interface.ipv6_addresses:
                    interface.requires_manual_review = True
                    if interface.migration_status == "NORMALIZED":
                        interface.migration_status = "PARTIALLY_NORMALIZED"
                self.config.interfaces.append(interface)
                continue

            match = re.match(r"^object\s+network\s+(\S+)", line, re.IGNORECASE)
            if match:
                i += 1
                block: List[str] = []
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    block.append(lines[i].strip())
                    i += 1
                obj = self._parse_network_object(match.group(1), block)
                self.config.network_objects.append(obj)
                if obj.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(
                        line_number, line, "Network object contains malformed or incomplete address syntax",
                        "object network", obj.name,
                    )
                for nat_line in obj.nat_lines:
                    self._parse_nat_line(nat_line, line_number, owning_object=obj.name)
                continue

            match = re.match(r"^object-group\s+network\s+(\S+)", line, re.IGNORECASE)
            if match:
                group = CiscoNetworkGroup(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("network-object host ") and len(parts) >= 3:
                        try:
                            address = ipaddress.ip_address(parts[2])
                            group.members.append(_safe_name("asa_inline_host", str(address)))
                            group.source_attributes.setdefault("member_families", []).append(f"ipv{address.version}")
                        except ValueError:
                            group.migration_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                    elif lower.startswith("network-object object ") and len(parts) >= 3:
                        group.members.append(parts[2])
                    elif lower.startswith("network-object ") and len(parts) >= 2:
                        value = None
                        family = None
                        if ":" in parts[1] and "/" in parts[1]:
                            try:
                                value = str(ipaddress.IPv6Network(parts[1], strict=False))
                                family = "ipv6"
                            except ValueError:
                                pass
                        elif len(parts) >= 3:
                            value = normalize_ipv4_network(parts[1], parts[2])
                            family = "ipv4" if value else None
                        if value:
                            group.members.append(_safe_name("asa_inline_net", value))
                            group.source_attributes.setdefault("member_families", []).append(family)
                        else:
                            group.migration_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                    elif lower.startswith("group-object ") and len(parts) >= 2:
                        group.members.append(parts[1])
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.migration_status = "PARTIALLY_NORMALIZED"
                        group.requires_manual_review = True
                    i += 1
                self.config.network_groups.append(group)
                families = set(group.source_attributes.get("member_families", []))
                group.address_family = next(iter(families)) if len(families) == 1 else "mixed" if families else None
                if group.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "Network group contains a malformed member", "object-group network", group.name)
                continue

            match = re.match(r"^object\s+network-service\s+(\S+)", line, re.IGNORECASE)
            if match:
                obj = CiscoNetworkServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    obj.raw_lines.append(sub)
                    parts = sub.split()
                    if sub.lower().startswith("description "):
                        obj.description = sub.split(maxsplit=1)[1]
                    elif parts:
                        obj.members.append(sub)
                    i += 1
                obj.source_attributes["combined_address_service_semantics"] = True
                self.config.network_service_objects.append(obj)
                continue

            match = re.match(r"^object-group\s+network-service\s+(\S+)", line, re.IGNORECASE)
            if match:
                group = CiscoNetworkServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    if sub.lower().startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.members.append(sub)
                    i += 1
                group.source_attributes["combined_address_service_semantics"] = True
                self.config.network_service_groups.append(group)
                continue

            match = re.match(r"^object-group\s+(protocol|icmp-type|user|security)\s+(\S+)", line, re.IGNORECASE)
            if match:
                group_type, group_name = match.group(1).lower(), match.group(2)
                group = CiscoNamedGroup(name=group_name, group_type=group_type)
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    if sub.lower().startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.members.append(sub)
                    i += 1
                target = {
                    "protocol": self.config.protocol_groups,
                    "icmp-type": self.config.icmp_type_groups,
                    "user": self.config.user_groups,
                    "security": self.config.security_groups,
                }[group_type]
                target.append(group)
                continue

            match = re.match(r"^object\s+service\s+(\S+)", line, re.IGNORECASE)
            if match:
                obj = CiscoServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    obj.raw_lines.append(sub)
                    if sub.lower().startswith("service "):
                        ports, error = parse_service_clause(sub.split()[1:])
                        obj.ports.extend(ports)
                        if error:
                            obj.migration_status = "PARSE_ERROR"
                            obj.requires_manual_review = True
                    elif sub.lower().startswith("description "):
                        obj.description = sub.split(maxsplit=1)[1]
                    else:
                        obj.migration_status = "PARTIALLY_NORMALIZED"
                        obj.requires_manual_review = True
                    i += 1
                if not obj.ports:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                self.config.service_objects.append(obj)
                if obj.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "Service object contains malformed or missing service syntax", "object service", obj.name)
                continue

            match = re.match(r"^object-group\s+service\s+(\S+)(?:\s+(\S+))?", line, re.IGNORECASE)
            if match:
                group = CiscoServiceGroup(name=match.group(1), protocol=match.group(2))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("group-object ") and len(parts) >= 2:
                        group.members.append(parts[1])
                    elif lower.startswith("service-object object ") and len(parts) >= 3:
                        group.members.append(parts[2])
                    elif lower.startswith("service-object "):
                        ports, error = parse_service_clause(parts[1:])
                        group.service_objects.extend(ports)
                        if error:
                            group.migration_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                    elif lower.startswith("port-object "):
                        if not group.protocol:
                            group.migration_status = "PARTIALLY_NORMALIZED"
                            group.requires_manual_review = True
                        else:
                            pseudo = [group.protocol, "destination", *parts[1:]]
                            ports, error = parse_service_clause(pseudo)
                            group.service_objects.extend(ports)
                            if error:
                                group.migration_status = "PARSE_ERROR"
                                group.requires_manual_review = True
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.migration_status = "PARTIALLY_NORMALIZED"
                        group.requires_manual_review = True
                    i += 1
                self.config.service_groups.append(group)
                if group.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "Service group contains malformed service syntax", "object-group service", group.name)
                continue

            match = re.match(r"^time-range\s+(\S+)", line, re.IGNORECASE)
            if match:
                schedule = CiscoTimeRange(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    schedule.raw_lines.append(sub)
                    parts = sub.split()
                    lower_parts = [part.lower() for part in parts]
                    if lower_parts and lower_parts[0] == "absolute":
                        clause = CiscoTimeRangeClause(clause_type="absolute", raw=sub)
                        if "start" in lower_parts:
                            start = lower_parts.index("start") + 1
                            end = lower_parts.index("end") if "end" in lower_parts else len(parts)
                            clause.start = " ".join(parts[start:end])
                        if "end" in lower_parts:
                            end = lower_parts.index("end") + 1
                            clause.end = " ".join(parts[end:])
                        if not clause.start and not clause.end:
                            schedule.migration_status = "PARSE_ERROR"
                            schedule.requires_manual_review = True
                            schedule.review_reasons.append("Malformed absolute time-range clause")
                        schedule.clauses.append(clause)
                    elif lower_parts and lower_parts[0] == "periodic" and "to" in lower_parts:
                        to_index = lower_parts.index("to")
                        if to_index >= 2 and to_index + 1 < len(parts):
                            schedule.clauses.append(CiscoTimeRangeClause(
                                clause_type="periodic", raw=sub,
                                days=lower_parts[1:to_index - 1],
                                start=parts[to_index - 1], end=parts[to_index + 1],
                            ))
                        else:
                            schedule.migration_status = "PARSE_ERROR"
                            schedule.requires_manual_review = True
                            schedule.review_reasons.append("Malformed periodic time-range clause")
                    else:
                        schedule.migration_status = "PARSE_ERROR"
                        schedule.requires_manual_review = True
                        schedule.review_reasons.append(f"Unparsed time-range clause: {sub}")
                    i += 1
                if len(schedule.clauses) > 1 and schedule.migration_status == "NORMALIZED":
                    schedule.migration_status = "PARTIALLY_NORMALIZED"
                    schedule.requires_manual_review = True
                    schedule.review_reasons.append("Multiple ASA time-range clauses are source-preserved")
                self.config.time_ranges.append(schedule)
                if schedule.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "; ".join(schedule.review_reasons), "time-range", schedule.name)
                continue

            if line.lower().startswith("access-list "):
                rule, error = parse_acl_line(line, line_number, remarks)
                if rule:
                    self.config.access_rules.append(rule)
                    if rule.migration_status == "PARSE_ERROR":
                        self._record_diagnostic(line_number, line, "; ".join(rule.review_reasons), "access-list", rule.acl_name)
                if error:
                    if error.startswith("Unsupported ACL type"):
                        self._record_unsupported(line_number, line, error)
                    else:
                        self._record_diagnostic(line_number, line, error, "access-list")
                i += 1
                continue
            if line.lower().startswith("access-group "):
                binding = parse_acl_binding(line, line_number)
                if binding:
                    self.config.acl_bindings.append(binding)
                    self._record_acl_consumer(binding.acl_name, "access-group", line_number, line)
                else:
                    self._record_diagnostic(line_number, line, "Malformed access-group binding", "access-group")
                i += 1
                continue
            consumer_patterns = (
                (r"^crypto\s+map\s+\S+\s+\S+\s+match\s+address\s+(\S+)", "crypto-map"),
                (r"^match\s+access-list\s+(\S+)", "class-map"),
                (r"^capture\s+\S+\s+.*\baccess-list\s+(\S+)", "capture"),
                (r"^aaa\s+.*\bmatch\s+(\S+)", "aaa"),
            )
            consumer_match = next(((re.match(pattern, line, re.IGNORECASE), kind) for pattern, kind in consumer_patterns if re.match(pattern, line, re.IGNORECASE)), None)
            if consumer_match:
                match_obj, kind = consumer_match
                self._record_acl_consumer(match_obj.group(1), kind, line_number, line)
                self._record_unsupported(line_number, line, f"{kind} ACL consumer is preserved as extract-only")
                i += 1
                continue
            if line.lower().startswith("nat "):
                self._parse_nat_line(line, line_number)
                i += 1
                continue
            if line.lower().startswith(("route ", "ipv6 route ")):
                route, error = self._parse_route_line(line)
                if route:
                    self.config.static_routes.append(route)
                if error:
                    self._record_diagnostic(line_number, line, error, "ipv6 route" if line.lower().startswith("ipv6") else "route")
                i += 1
                continue
            route_map_match = re.match(r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)$", line, re.IGNORECASE)
            if route_map_match:
                route_map = CiscoRouteMap(name=route_map_match.group(1), raw_lines=[line])
                rule = CiscoRouteMapRule(
                    name=route_map.name, sequence=int(route_map_match.group(3)),
                    action=route_map_match.group(2).lower(), raw_lines=[line],
                    source_attributes={"raw_header": line},
                )
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    rule.raw_lines.append(sub)
                    route_map.raw_lines.append(sub)
                    match_acl = re.match(r"^match\s+access-list\s+(\S+)$", sub, re.IGNORECASE)
                    next_hop = re.match(r"^set\s+ip\s+next-hop\s+(\S+)$", sub, re.IGNORECASE)
                    set_interface = re.match(r"^set\s+interface\s+(\S+)$", sub, re.IGNORECASE)
                    if match_acl:
                        rule.match_acl = match_acl.group(1)
                    elif next_hop:
                        rule.set_next_hop = next_hop.group(1)
                    elif set_interface:
                        rule.set_interface = set_interface.group(1)
                    else:
                        rule.raw_options.append(sub)
                    i += 1
                existing = next((item for item in self.config.route_maps if item.name == route_map.name), None)
                if existing is None:
                    route_map.rules.append(rule)
                    self.config.route_maps.append(route_map)
                else:
                    existing.rules.append(rule)
                    existing.raw_lines.extend(route_map.raw_lines)
                continue
            self._record_unsupported(line_number, line, "No Cisco ASA extraction handler")
            i += 1
        return self.config

    def _parse_route_line(self, line: str) -> Tuple[Optional[CiscoStaticRoute], Optional[str]]:
        tokens = line.split()
        ipv6 = len(tokens) >= 2 and tokens[0].lower() == "ipv6" and tokens[1].lower() == "route"
        index = 2 if ipv6 else 1
        required = 3 if ipv6 else 4
        interface = tokens[index] if len(tokens) > index else None
        if len(tokens) - index < required:
            return CiscoStaticRoute(interface=interface, address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
                                    migration_status="PARSE_ERROR", requires_manual_review=True), "Incomplete static route statement"
        if ipv6:
            destination, mask, gateway = tokens[index + 1], None, tokens[index + 2]
            index += 3
            try:
                destination = str(ipaddress.IPv6Network(destination, strict=False))
                ipaddress.IPv6Address(gateway)
            except ValueError:
                return CiscoStaticRoute(
                    interface=interface, destination=destination, gateway=gateway,
                    address_family="ipv6", raw_line=line, migration_status="PARSE_ERROR",
                    requires_manual_review=True,
                ), "Invalid IPv6 route prefix or next hop"
        else:
            destination, mask, gateway = tokens[index + 1:index + 4]
            index += 4
            try:
                ipaddress.IPv4Address(gateway)
            except ValueError:
                return CiscoStaticRoute(interface=interface, destination=destination, mask=mask, gateway=gateway,
                                        address_family="ipv4", raw_line=line, migration_status="PARSE_ERROR",
                                        requires_manual_review=True), "Invalid IPv4 route next hop"
        route = CiscoStaticRoute(
            interface=interface, destination=destination, mask=mask, gateway=gateway,
            address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
        )
        if not ipv6 and normalize_ipv4_network(destination, mask or "") is None:
            route.migration_status = "PARSE_ERROR"
            route.requires_manual_review = True
            return route, "Invalid IPv4 route destination/netmask"
        while index < len(tokens):
            token = tokens[index].lower()
            if token.isdigit() and route.administrative_distance is None:
                route.administrative_distance = int(token)
                index += 1
            elif token == "track" and index + 1 < len(tokens) and tokens[index + 1].isdigit():
                route.track_id = int(tokens[index + 1])
                index += 2
            elif token == "tunneled":
                route.tunneled = True
                index += 1
            else:
                route.raw_options.append(tokens[index])
                index += 1
        if route.track_id is not None:
            route.review_reasons.append("Route tracking dependency requires target review")
        if route.tunneled:
            route.review_reasons.append("ASA tunneled route semantics require target review")
        if route.raw_options:
            route.review_reasons.append(f"Unparsed route options: {' '.join(route.raw_options)}")
        if route.review_reasons:
            route.migration_status = "PARTIALLY_NORMALIZED"
            route.requires_manual_review = True
        return route, None

    def _parse_nat_line(self, line: str, line_number: int, owning_object: Optional[str] = None) -> None:
        match = re.match(r"^nat(?:\s+\(([^,]*),([^)]*)\))?\s+(.+)$", line, re.IGNORECASE)
        if not match:
            self._record_diagnostic(line_number, line, "Malformed NAT statement", "nat")
            return
        src_if = match.group(1).strip() or None if match.group(1) is not None else None
        dst_if = match.group(2).strip() or None if match.group(2) is not None else None
        tail = match.group(3).split()
        section = "after-auto" if tail and tail[0].lower() == "after-auto" else "object" if owning_object else "manual"
        if section == "after-auto":
            tail = tail[1:]
        sequence = None
        if tail and tail[0].isdigit():
            sequence = int(tail.pop(0))
        self._nat_section_counts[section] = self._nat_section_counts.get(section, 0) + 1
        within = self._nat_section_counts[section]
        section_order = {"manual": 1, "object": 2, "after-auto": 3}[section]
        rule = CiscoNATRule(
            name=f"nat_{section}_{line_number}", source_interface=src_if, destination_interface=dst_if,
            section=section, sequence=sequence, source_sequence=sequence, owning_object=owning_object,
            source_order=line_number, source_order_within_section=within, section_order=section_order,
            effective_source_order=section_order * 1_000_000 + (sequence if sequence is not None else within),
            raw_line=line,
        )
        index = 0

        def parse_mapped_source(position: int) -> int:
            if position >= len(tail):
                return position
            token = tail[position]
            lower = token.lower()
            if lower == "interface":
                rule.mapped_source_mode = "interface"
                rule.mapped_source = "interface"
                position += 1
                if position < len(tail) and tail[position].lower() == "ipv6":
                    rule.mapped_source_address_family = "ipv6"
                    position += 1
                return position
            if lower == "pat-pool":
                rule.mapped_source_mode = "pat_pool"
                if position + 1 < len(tail):
                    rule.pat_pool = tail[position + 1]
                    rule.mapped_source = rule.pat_pool
                    position += 2
                    while position < len(tail) and tail[position].lower() in {
                        "round-robin", "extended", "flat", "include-reserve", "block-allocation"
                    }:
                        rule.pat_pool_options.append(tail[position])
                        position += 1
                return position
            rule.mapped_source_mode = rule.source_mode
            rule.mapped_source = token
            return position + 1

        if owning_object:
            if index < len(tail) and tail[index].lower() in {"static", "dynamic"}:
                rule.source_mode = tail[index].lower()
                rule.real_source = owning_object
                index = parse_mapped_source(index + 1)
            else:
                rule.review_reasons.append("Object NAT is missing static/dynamic translation mode")
        elif index < len(tail) and tail[index].lower() == "source":
            if index + 2 < len(tail):
                rule.source_mode = tail[index + 1].lower()
                rule.real_source = tail[index + 2]
                index = parse_mapped_source(index + 3)
            else:
                index = len(tail)
                rule.review_reasons.append("Incomplete NAT source clause")

        if index < len(tail) and tail[index].lower() == "destination":
            if index + 3 < len(tail):
                rule.destination_mode = tail[index + 1].lower()
                # Cisco twice-NAT grammar is destination static MAPPED REAL.
                rule.mapped_destination = tail[index + 2]
                rule.real_destination = tail[index + 3]
                index += 4
            else:
                rule.review_reasons.append("Incomplete NAT destination clause")
                index = len(tail)

        if index < len(tail) and tail[index].lower() == "service":
            if index + 3 < len(tail):
                rule.service_protocol = tail[index + 1].lower()
                rule.original_service = tail[index + 2]
                rule.translated_service = tail[index + 3]
                index += 4
            elif index + 2 < len(tail):
                rule.original_service = tail[index + 1]
                rule.translated_service = tail[index + 2]
                index += 3
            else:
                rule.review_reasons.append("Incomplete NAT service translation")
                index = len(tail)

        option_names = {
            "dns", "no-proxy-arp", "route-lookup", "unidirectional", "inactive", "net-to-net",
            "round-robin", "extended", "flat", "include-reserve", "block-allocation",
        }
        while index < len(tail):
            token = tail[index]
            lower = token.lower()
            if lower == "description":
                rule.description = " ".join(tail[index + 1:]) or None
                index = len(tail)
            elif lower in option_names:
                rule.options.append(lower)
                if lower in {"round-robin", "extended", "flat", "include-reserve", "block-allocation"}:
                    rule.pat_pool_options.append(lower)
                index += 1
            else:
                rule.raw_options.append(token)
                index += 1

        rule.dns = "dns" in rule.options
        rule.no_proxy_arp = "no-proxy-arp" in rule.options
        rule.route_lookup = "route-lookup" in rule.options
        rule.unidirectional = "unidirectional" in rule.options
        rule.inactive = "inactive" in rule.options
        rule.net_to_net = "net-to-net" in rule.options

        if not rule.real_source or not rule.mapped_source:
            rule.migration_status = "PARSE_ERROR"
            rule.requires_manual_review = True
            rule.review_reasons.append("NAT source translation operands are incomplete")
        partial_details = []
        if rule.destination_mode:
            partial_details.append("twice-NAT destination translation")
        if rule.original_service:
            partial_details.append("service/PAT translation")
        if rule.mapped_source_address_family == "ipv6":
            partial_details.append("interface IPv6 translation")
        if rule.pat_pool_options:
            partial_details.append(f"PAT pool modifiers: {' '.join(rule.pat_pool_options)}")
        noncanonical_options = [opt for opt in rule.options if opt != "inactive"]
        if noncanonical_options:
            partial_details.append(f"NAT modifiers: {' '.join(noncanonical_options)}")
        if rule.raw_options:
            partial_details.append(f"Unparsed NAT tokens: {' '.join(rule.raw_options)}")
        if partial_details and rule.migration_status != "PARSE_ERROR":
            rule.migration_status = "PARTIALLY_NORMALIZED"
            rule.requires_manual_review = True
            rule.review_reasons.extend(partial_details)
        if rule.migration_status == "PARSE_ERROR":
            self._record_diagnostic(line_number, line, "; ".join(rule.review_reasons), "nat", owning_object)
        self.config.nat_rules.append(rule)

    @staticmethod
    def _protocol(protocol: str) -> Optional[ServiceProtocol]:
        return {
            "tcp": ServiceProtocol.TCP, "udp": ServiceProtocol.UDP, "sctp": ServiceProtocol.SCTP,
            "icmp": ServiceProtocol.ICMP, "icmp6": ServiceProtocol.ICMPV6, "ip": ServiceProtocol.IP,
        }.get(protocol.lower())

    @staticmethod
    def _port_values(spec: Optional[CiscoPortSpec]) -> Optional[List[str]]:
        if spec is None:
            return []
        if spec.operator == "eq" and spec.values:
            return [spec.values[0]]
        if spec.operator == "range" and len(spec.values) == 2:
            return [f"{spec.values[0]}-{spec.values[1]}"]
        if spec.operator in {"lt", "gt", "neq"} and spec.values:
            try:
                value = int(spec.values[0])
            except ValueError:
                return None
            if not 1 <= value <= 65535:
                return None
            if spec.operator == "lt":
                return [f"1-{value - 1}"] if value > 1 else []
            if spec.operator == "gt":
                return [f"{value + 1}-65535"] if value < 65535 else []
            result = []
            if value > 1:
                result.append(f"1-{value - 1}")
            if value < 65535:
                result.append(f"{value + 1}-65535")
            return result
        return None

    def _ir_service_ports(self, ports: Iterable[CiscoServicePort]) -> Tuple[List[IRServicePort], List[str]]:
        result: List[IRServicePort] = []
        errors: List[str] = []
        for item in ports:
            protocol = self._protocol(item.protocol)
            if protocol is None:
                protocol = ServiceProtocol.IP
                errors.append(f"IP protocol '{item.protocol}' is source-preserved and requires target capability review")
            destinations = self._port_values(item.destination)
            sources = self._port_values(item.source)
            if item.destination and destinations is None:
                errors.append(f"Unsupported destination-port operator '{item.destination.operator}'")
                continue
            if item.source and sources is None:
                errors.append(f"Unsupported source-port operator '{item.source.operator}'")
                continue
            destinations = destinations or ["any" if protocol in {ServiceProtocol.ICMP, ServiceProtocol.ICMPV6, ServiceProtocol.IP} else "1-65535"]
            sources = sources or [None]
            icmp_type = int(item.icmp_type) if item.icmp_type and item.icmp_type.isdigit() else None
            for destination in destinations:
                for source in sources:
                    result.append(IRServicePort(
                        protocol=protocol, port=destination, source_port=source, raw_source_value=item.raw,
                        icmptype=icmp_type, icmpcode=item.icmp_code,
                    ))
            if item.icmp_type and icmp_type is None:
                errors.append(f"Named ICMP type '{item.icmp_type}' requires review")
        return result, errors

    def transform_to_ir(self) -> IRConfig:
        cfg = self.parse_raw()
        ir = IRConfig(metadata=IRMetadata(hostname=cfg.hostname, source_vendor="cisco_asa", source_product="Cisco ASA"))

        explicit_zones: Dict[str, IRZone] = {}
        for interface in cfg.interfaces:
            zone = interface.nameif or self.zone_mapping.get(interface.name)
            if zone:
                explicit_zones.setdefault(zone, IRZone(name=zone)).interfaces.append(interface.name)
            ip_value = normalize_ipv4_network(interface.ip or "", interface.mask or "") if interface.ip_mode == "static" else None
            parse_errors = []
            if interface.ip_mode == "static" and ip_value is None:
                parse_errors.append(f"Invalid IPv4 address/netmask: {interface.ip or ''} {interface.mask or ''}".strip())
            ir.interfaces.append(IRInterface(
                name=interface.name, zone=zone, ip=ip_value, description=interface.description,
                status=not interface.shutdown, addressing_mode=interface.ip_mode,
                interface_type=interface.interface_type, parent=interface.parent_interface,
                vlanid=interface.vlan_id, mtu=interface.mtu, members=interface.redundant_interface_members,
                dhcp_client=True if interface.ip_mode == "dhcp" else None,
                ipv6_source_settings={
                    "addresses": [item.model_dump() for item in interface.ipv6_addresses],
                    "autoconfig": interface.ipv6_autoconfig,
                    "dhcp": interface.ipv6_dhcp,
                    "dhcp_setroute": interface.ipv6_dhcp_setroute,
                },
                requires_manual_review=interface.requires_manual_review or bool(parse_errors),
                parse_errors=parse_errors, source_attributes={
                    **interface.source_attributes,
                    "nameif": interface.nameif,
                    "security_level": interface.security_level,
                    "standby_ip": interface.standby_ip,
                    "dhcp_setroute": interface.dhcp_setroute,
                    "management_only": interface.management_only,
                    "interface_type": interface.interface_type,
                    "parent_interface": interface.parent_interface,
                    "vlan_id": interface.vlan_id,
                    "port_channel_id": interface.port_channel_id,
                    "channel_group": interface.channel_group,
                    "channel_group_mode": interface.channel_group_mode,
                    "redundant_interface_members": interface.redundant_interface_members,
                    "bridge_group": interface.bridge_group,
                    "bvi_id": interface.bvi_id,
                    "routing_context": interface.routing_context,
                    "vrf": interface.vrf,
                    "administrative_state": interface.administrative_state,
                    "policy_route_maps": interface.policy_route_maps,
                    "raw_lines": interface.raw_lines,
                },
                migration_status=interface.migration_status,
            ))
        ir.zones = list(explicit_zones.values())

        inline_addresses: Dict[str, IRAddress] = {}
        for obj in cfg.network_objects:
            if obj.type is None or obj.value is None:
                continue
            kwargs = dict(
                name=obj.name, description=obj.description, source_type=obj.type,
                address_family=obj.address_family,
                source_attributes={**obj.source_attributes, "raw_lines": obj.raw_lines},
                migration_status=obj.migration_status, requires_manual_review=obj.requires_manual_review,
            )
            if obj.type == "host":
                kwargs.update(type=AddressType.HOST, subnet=obj.value, is_ipv6=obj.address_family == "ipv6")
            elif obj.type == "subnet":
                kwargs.update(type=AddressType.NETWORK, subnet=obj.value, is_ipv6=obj.address_family == "ipv6")
            elif obj.type == "range":
                start, end = obj.value.split("-", 1)
                kwargs.update(type=AddressType.RANGE, ip_range_start=start, ip_range_end=end, is_ipv6=obj.address_family == "ipv6")
            else:
                kwargs.update(type=AddressType.FQDN, fqdn=obj.value)
            ir.addresses.append(IRAddress(**kwargs))

        for group in cfg.network_groups:
            for raw in group.raw_lines:
                parts = raw.split()
                if raw.lower().startswith("network-object host ") and len(parts) >= 3:
                    name = _safe_name("asa_inline_host", parts[2])
                    family = "ipv6" if ":" in parts[2] else "ipv4"
                    inline_addresses[name] = IRAddress(name=name, type=AddressType.HOST, subnet=parts[2], raw_value=raw, address_family=family, is_ipv6=family == "ipv6")
                elif raw.lower().startswith("network-object ") and len(parts) >= 2 and parts[1].lower() not in {"object", "host"}:
                    value = None
                    family = None
                    if ":" in parts[1] and "/" in parts[1]:
                        try:
                            value = str(ipaddress.IPv6Network(parts[1], strict=False))
                            family = "ipv6"
                        except ValueError:
                            pass
                    elif len(parts) >= 3:
                        value = normalize_ipv4_network(parts[1], parts[2])
                        family = "ipv4" if value else None
                    if value:
                        name = _safe_name("asa_inline_net", value)
                        inline_addresses[name] = IRAddress(name=name, type=AddressType.NETWORK, subnet=value, raw_value=raw, address_family=family, is_ipv6=family == "ipv6")
            ir.address_groups.append(IRAddressGroup(
                name=group.name, members=group.members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                address_family=group.address_family,
                source_attributes={**group.source_attributes, "raw_lines": group.raw_lines},
            ))

        for obj in cfg.service_objects:
            ports, errors = self._ir_service_ports(obj.ports)
            if not ports:
                continue
            ir.services.append(IRService(
                name=obj.name, ports=ports, description=obj.description,
                source_protocol=obj.ports[0].protocol if len({item.protocol for item in obj.ports}) == 1 else None,
                source_protocol_number=int(obj.ports[0].protocol) if len(obj.ports) == 1 and obj.ports[0].protocol.isdigit() else None,
                source_attributes={"raw_lines": obj.raw_lines},
                migration_status="PARTIALLY_NORMALIZED" if errors else obj.migration_status,
                requires_manual_review=obj.requires_manual_review or bool(errors),
                audit_note="; ".join(errors) or None,
            ))

        for group in cfg.service_groups:
            members = list(group.members)
            if group.service_objects:
                name = _safe_name("asa_group_service", group.name)
                ports, errors = self._ir_service_ports(group.service_objects)
                if ports:
                    ir.services.append(IRService(
                        name=name, ports=ports, description=f"Inline services for {group.name}",
                        source_protocol=group.protocol,
                        migration_status="PARTIALLY_NORMALIZED" if errors else group.migration_status,
                        requires_manual_review=group.requires_manual_review or bool(errors),
                        audit_note="; ".join(errors) or None,
                    ))
                    members.append(name)
            ir.service_groups.append(IRServiceGroup(
                name=group.name, members=members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                source_attributes={"protocol": group.protocol, "raw_lines": group.raw_lines},
            ))

        for group in [*cfg.protocol_groups, *cfg.icmp_type_groups]:
            members: List[str] = []
            for raw in group.members:
                parts = raw.split()
                if len(parts) >= 2 and parts[0].lower() in {"protocol-object", "icmp-object"}:
                    value = parts[1]
                    service_name = _safe_name(f"asa_{group.group_type}", f"{group.name}:{value}")
                    protocol_value = value if group.group_type == "protocol" else "icmp"
                    source_port = CiscoServicePort(
                        protocol=protocol_value,
                        icmp_type=value if group.group_type == "icmp-type" else None,
                        raw=raw,
                    )
                    ports, errors = self._ir_service_ports([source_port])
                    if ports:
                        ir.services.append(IRService(
                            name=service_name, ports=ports, source_protocol=protocol_value,
                            source_protocol_number=int(value) if value.isdigit() and group.group_type == "protocol" else None,
                            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
                            audit_note="; ".join(errors) or f"ASA {group.group_type} member requires target review",
                            source_attributes={"raw_line": raw, "owning_group": group.name},
                        ))
                        members.append(service_name)
                elif len(parts) >= 2 and parts[0].lower() == "group-object":
                    members.append(parts[1])
            ir.service_groups.append(IRServiceGroup(
                name=group.name, members=members, unsafe_members=list(members),
                description=group.description, migration_status="PARTIALLY_NORMALIZED",
                requires_manual_review=True,
                source_attributes={"group_type": group.group_type, "raw_lines": group.raw_lines},
            ))

        for schedule in cfg.time_ranges:
            first = schedule.clauses[0] if schedule.clauses else None
            ir.schedules.append(IRSchedule(
                name=schedule.name,
                start=first.start if first else None,
                end=first.end if first else None,
                days=first.days if first else [],
                schedule_type=first.clause_type if first else "source-only",
                source_attributes={
                    "clauses": [item.model_dump() for item in schedule.clauses],
                    "raw_lines": schedule.raw_lines,
                    "migration_status": schedule.migration_status,
                    "requires_manual_review": schedule.requires_manual_review,
                    "review_reasons": schedule.review_reasons,
                },
            ))

        synthetic_services: Dict[str, IRService] = {}

        def endpoint_reference(rule: CiscoAccessRule, source: bool) -> List[str]:
            endpoint = rule.source_endpoint if source else rule.destination_endpoint
            if endpoint is None or not endpoint.valid or endpoint.value is None:
                return []
            if endpoint.type == "any":
                if endpoint.value == "any4":
                    rule.requires_manual_review = True
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("IPv4-only universal address requires family-aware target support")
                    return [IR_KEYWORD_ANY_IPV4]
                if endpoint.value == "any6":
                    rule.requires_manual_review = True
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("IPv6-only universal address requires family-aware target support")
                    return [IR_KEYWORD_ANY_IPV6]
                return [IR_KEYWORD_ANY]
            if endpoint.type in {"inline", "host"}:
                value = endpoint.value
                if endpoint.type == "host" and "/" not in value:
                    value = f"{value}/128" if ":" in value else f"{value}/32"
                prefix = "asa_inline_host" if endpoint.type == "host" or "/32" in value or "/128" in value else "asa_inline_net"
                name = _safe_name(prefix, value)
                addr_type = AddressType.HOST if prefix.endswith("host") else AddressType.NETWORK
                inline_addresses[name] = IRAddress(
                    name=name, type=addr_type, subnet=value, raw_value=endpoint.raw,
                    address_family=endpoint.address_family, is_ipv6=endpoint.address_family == "ipv6",
                )
                return [name]
            if endpoint.type in {"interface", "object-group-network-service"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append(
                    "Interface-address endpoint cannot be converted safely" if endpoint.type == "interface"
                    else "Network-service endpoint combines address and service semantics"
                )
                return []
            return [endpoint.value]

        def service_reference(rule: CiscoAccessRule) -> List[str]:
            if rule.protocol in {"object", "object-group"} and rule.protocol_object:
                return [rule.protocol_object]
            if rule.icmp_object_group:
                return [rule.icmp_object_group]
            if rule.destination_port and rule.destination_port.operator in {"object", "object-group"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Referenced ACL port object/group requires target service validation")
                return [rule.destination_port.object_name] if rule.destination_port.object_name else []
            if rule.source_port and rule.source_port.operator in {"object", "object-group"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Source-port object/group relationship is source-preserved")
                return []
            if rule.protocol == "ip" and not rule.destination_port and not rule.source_port:
                return [IR_KEYWORD_ANY]
            if (rule.protocol or "").lower() not in KNOWN_PROTOCOLS and not (rule.protocol or "").isdigit():
                return []
            port_model = CiscoServicePort(
                protocol=rule.protocol or "", source=rule.source_port, destination=rule.destination_port,
                icmp_type=rule.icmp_type, icmp_code=rule.icmp_code, raw=rule.raw_line,
            )
            ports, errors = self._ir_service_ports([port_model])
            if not ports:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
                return []
            expression = f"{rule.protocol}:{rule.source_port.raw if rule.source_port else '*'}:{rule.destination_port.raw if rule.destination_port else '*'}:{rule.icmp_type or ''}"
            name = _safe_name("asa_inline_service", expression)
            if errors:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
            source_protocol = rule.protocol or ""
            synthetic_services[name] = IRService(
                name=name, ports=ports,
                source_protocol=source_protocol,
                source_protocol_number=int(source_protocol) if source_protocol.isdigit() else None,
                migration_status="PARTIALLY_NORMALIZED" if errors else "NORMALIZED",
                requires_manual_review=bool(errors), audit_note="; ".join(errors) or None,
                source_attributes={"source_expression": expression},
            )
            return [name]

        bindings: Dict[str, List] = {}
        for binding in cfg.acl_bindings:
            bindings.setdefault(binding.acl_name, []).append(binding)
        interface_zones = {interface.nameif: (interface.nameif or self.zone_mapping.get(interface.name)) for interface in cfg.interfaces if interface.nameif}
        interface_zones.update({interface.name: (interface.nameif or self.zone_mapping.get(interface.name)) for interface in cfg.interfaces})

        for rule in cfg.access_rules:
            rule_bindings = bindings.get(rule.acl_name) or []
            # ACL definitions used by crypto, class-map, capture, AAA, or no known
            # consumer are retained in the source model and are not transit rules.
            if not rule_bindings:
                continue
            for binding in rule_bindings:
                from_zone: List[str] = []
                to_zone: List[str] = []
                source_from: List[str] = []
                source_to: List[str] = []
                review = list(rule.review_reasons)
                status = rule.migration_status
                manual = rule.requires_manual_review
                extra = {"acl_name": rule.acl_name, "raw_line": rule.raw_line}
                suffix = "unbound"
                if binding is not None:
                    suffix = f"{binding.interface or 'global'}_{binding.direction or 'unknown'}"
                    extra.update({
                        "binding_direction": binding.direction, "binding_interface": binding.interface,
                        "global": binding.direction == "global", "control_plane": binding.control_plane,
                        "per_user_override": binding.per_user_override,
                    })
                    zone = interface_zones.get(binding.interface or "")
                    if binding.direction == "in":
                        source_from = [binding.interface] if binding.interface else []
                        from_zone = [zone] if zone else []
                    elif binding.direction == "out":
                        source_to = [binding.interface] if binding.interface else []
                        to_zone = [zone] if zone else []
                    if binding.direction == "global" or binding.control_plane or not zone and binding.direction != "global":
                        manual = True
                        status = "EXTRACT_ONLY" if binding.control_plane else "PARTIALLY_NORMALIZED"
                        review.append("ACL binding context cannot be represented as an ordinary transit policy")
                source_refs = endpoint_reference(rule, True)
                destination_refs = endpoint_reference(rule, False)
                services = service_reference(rule)
                manual = manual or rule.requires_manual_review
                if rule.migration_status != "NORMALIZED":
                    status = rule.migration_status
                review.extend(reason for reason in rule.review_reasons if reason not in review)
                if not source_refs or not destination_refs or not services:
                    manual = True
                    status = "PARSE_ERROR" if status == "NORMALIZED" else status
                    review.append("Policy has unresolved address or service semantics")
                if rule.time_range:
                    schedule = next((item for item in cfg.time_ranges if item.name == rule.time_range), None)
                    if schedule is None:
                        manual = True
                        status = "PARTIALLY_NORMALIZED"
                        review.append(f"Schedule '{rule.time_range}' is unresolved")
                    elif schedule.requires_manual_review:
                        manual = True
                        status = "PARTIALLY_NORMALIZED"
                        review.extend(schedule.review_reasons or [f"Schedule '{rule.time_range}' requires review"])
                name = f"{rule.id}__{re.sub(r'[^A-Za-z0-9_]+', '_', suffix)}"
                ir.policies.append(IRPolicy(
                    name=name, source_rule_id=rule.id, from_zone=from_zone, to_zone=to_zone,
                    source=source_refs, destination=destination_refs, service=services,
                    action=PolicyAction.ALLOW if rule.action == "permit" else PolicyAction.DENY if rule.action == "deny" else None,
                    source_from_interfaces=source_from, source_to_interfaces=source_to,
                    source_address_references=source_refs, destination_address_references=destination_refs,
                    source_service_references=services, source_action=rule.action,
                    source_schedule=rule.time_range, schedule=rule.time_range,
                    source_users=[rule.user] if rule.user else [], source_user_groups=[rule.user_group] if rule.user_group else [],
                    identity_dependency_review=bool(rule.user or rule.user_group), source_log_setting=rule.log_raw,
                    source_extra_settings=extra | {
                        "source_security_group_type": rule.source_security_group_type,
                        "source_security_group_value": rule.source_security_group_value,
                        "destination_security_group_type": rule.destination_security_group_type,
                        "destination_security_group_value": rule.destination_security_group_value,
                        "icmp_object_group": rule.icmp_object_group,
                    },
                    migration_status=status, review_reasons=list(dict.fromkeys(review)), requires_manual_review=manual,
                    description=rule.remark, disabled=rule.inactive, log_end=rule.log_enabled,
                ))

        ir.addresses.extend(inline_addresses.values())
        ir.services.extend(synthetic_services.values())

        address_names = {item.name for item in ir.addresses} | {item.name for item in ir.address_groups} | {
            IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6,
        }
        service_names = {item.name for item in ir.services} | {item.name for item in ir.service_groups} | {IR_KEYWORD_ANY}
        unsafe_addresses = {
            item.name for item in [*ir.addresses, *ir.address_groups]
            if item.requires_manual_review or item.migration_status != "NORMALIZED"
        }
        unsafe_services = {
            item.name for item in [*ir.services, *ir.service_groups]
            if item.requires_manual_review or item.migration_status != "NORMALIZED"
        }
        for policy in ir.policies:
            unresolved = [ref for ref in policy.source + policy.destination if ref not in address_names]
            unresolved += [ref for ref in policy.service if ref not in service_names]
            if unresolved:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"Unresolved references: {', '.join(sorted(set(unresolved)))}")
            unsafe = set(policy.source + policy.destination).intersection(unsafe_addresses)
            unsafe.update(set(policy.service).intersection(unsafe_services))
            if unsafe:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"References source semantics requiring review: {', '.join(sorted(unsafe))}")

        ordered_nat_rules = sorted(cfg.nat_rules, key=lambda item: item.effective_source_order or 0)
        for index, nat in enumerate(ordered_nat_rules, 1):
            source = [nat.real_source] if nat.real_source else []
            # ASA destination twice-NAT is written MAPPED REAL: the first
            # operand matches the original packet and the second is translated.
            destination = [nat.mapped_destination] if nat.mapped_destination else []
            services = [nat.original_service] if nat.original_service else [IR_KEYWORD_ANY] if source else []
            nat_type = NATType.TWICE if nat.destination_mode else NATType.SOURCE
            translated_refs = [ref for ref in [nat.mapped_source, nat.real_destination] if ref and ref != "interface"]
            def unresolved_nat_ref(ref: str) -> bool:
                if ref in address_names or ref in {"any", "interface"}:
                    return False
                try:
                    ipaddress.ip_address(ref)
                    return False
                except ValueError:
                    return True
            missing_refs = [ref for ref in source + destination + translated_refs if unresolved_nat_ref(ref)]
            manual = nat.requires_manual_review or bool(missing_refs)
            status = "PARTIALLY_NORMALIZED" if manual and nat.migration_status == "NORMALIZED" else nat.migration_status
            reasons = list(nat.review_reasons)
            if missing_refs:
                reasons.append(f"Unresolved NAT references: {', '.join(sorted(set(missing_refs)))}")
            ir.nat_rules.append(IRNATRule(
                name=nat.name, type=nat_type, sequence=nat.sequence if nat.sequence is not None else index,
                enabled="inactive" not in nat.options,
                source_from_interfaces=[nat.source_interface] if nat.source_interface else [],
                source_to_interfaces=[nat.destination_interface] if nat.destination_interface else [],
                from_zone=[nat.source_interface] if nat.source_interface else [], to_zone=[nat.destination_interface] if nat.destination_interface else [],
                source=source, destination=destination, services=services,
                source_translation_mode=(
                    NATTranslationMode.INTERFACE_ADDRESS if nat.mapped_source_mode == "interface"
                    else NATTranslationMode.POOL if nat.mapped_source_mode == "pat_pool"
                    else NATTranslationMode.STATIC if nat.source_mode == "static"
                    else NATTranslationMode.DYNAMIC_IP_AND_PORT if nat.source_mode == "dynamic"
                    else None
                ),
                source_pool_references=[nat.pat_pool] if nat.pat_pool else [],
                translated_sources=[nat.mapped_source] if nat.mapped_source else [],
                translated_destinations=[nat.real_destination] if nat.real_destination else [],
                translated_services=[nat.translated_service] if nat.translated_service else [],
                source_rule_id=str(nat.sequence or index), source_attributes={
                    "section": nat.section, "section_order": nat.section_order,
                    "source_sequence": nat.source_sequence,
                    "source_order_within_section": nat.source_order_within_section,
                    "effective_source_order": nat.effective_source_order,
                    "owning_object": nat.owning_object, "source_mode": nat.source_mode,
                    "mapped_source_mode": nat.mapped_source_mode,
                    "mapped_source_address_family": nat.mapped_source_address_family,
                    "pat_pool": nat.pat_pool, "pat_pool_options": nat.pat_pool_options,
                    "destination_mode": nat.destination_mode,
                    "service_protocol": nat.service_protocol,
                    "dns": nat.dns, "no_proxy_arp": nat.no_proxy_arp,
                    "route_lookup": nat.route_lookup, "unidirectional": nat.unidirectional,
                    "inactive": nat.inactive, "net_to_net": nat.net_to_net,
                    "options": nat.options, "raw_options": nat.raw_options, "raw_line": nat.raw_line,
                }, migration_status=status, requires_manual_review=manual, review_reasons=reasons,
            ))

        for index, route in enumerate(cfg.static_routes, 1):
            destination = route.destination if route.address_family == "ipv6" else normalize_ipv4_network(route.destination, route.mask or "")
            errors = [] if destination else [f"Invalid route destination/netmask: {route.destination} {route.mask or ''}".strip()]
            ir.routes.append(IRRoute(
                name=f"route_{route.interface}_{index}", destination=destination,
                address_family=route.address_family,
                source_destination=route.destination if route.address_family == "ipv6" else f"{route.destination} {route.mask}", interface=route.interface,
                next_hop=route.gateway, administrative_distance=route.administrative_distance,
                migration_status="PARSE_ERROR" if errors else route.migration_status,
                parse_error=errors[0] if errors else None, review_reasons=errors + route.review_reasons,
                requires_manual_review=route.requires_manual_review or bool(errors),
            source_attributes={
                "raw_line": route.raw_line, "track_id": route.track_id,
                "tunneled": route.tunneled, "raw_options": route.raw_options,
                "routing_context": route.routing_context,
                **route.source_attributes,
            },
            ))
        return ir
