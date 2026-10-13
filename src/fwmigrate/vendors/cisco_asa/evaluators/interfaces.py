"""ASA interface command syntax and evaluation."""

from __future__ import annotations

import re
import ipaddress
from typing import Any, Dict, Optional

from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.vendors.cisco_asa.model.interface import CiscoIPv6Address, CiscoInterface
from fwmigrate.vendors.cisco_asa.model.dhcp import CiscoDHCPRelay, CiscoDHCPRelayServer
from fwmigrate.vendors.cisco_asa.model.routing import CiscoPolicyRoutePathMonitor
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network
from . import _mark_explicit


def _parse_interface_header(header: str) -> Optional[Dict[str, Any]]:
    match = re.fullmatch(r"interface\s+(.+?)\s*", header.strip(), re.I)
    if not match:
        return None
    value = match.group(1)
    logical = re.fullmatch(r"(BVI|Redundant|Port-channel|Vlan)\s*(\d+)(?:\.(\d+))?", value, re.I)
    if logical:
        family, number, suffix = logical.groups()
        label = {"bvi": "BVI", "redundant": "Redundant", "port-channel": "Port-channel", "vlan": "Vlan"}[family.lower()]
        name = f"{label}{number}" + (f".{suffix}" if suffix else "")
        kind = "subinterface" if suffix else {"bvi": "bvi", "redundant": "redundant", "port-channel": "port-channel", "vlan": "vlan"}[family.lower()]
        return {"name": name, "interface_type": kind, "parent_interface": f"{label}{number}" if suffix else None,
                "interface_suffix_vlan_id": int(suffix) if suffix else None,
                "bvi_id": int(number) if family.lower() == "bvi" and not suffix else None,
                "port_channel_id": int(number) if family.lower() == "port-channel" and not suffix else None,
                "vlan_id": int(number) if family.lower() == "vlan" and not suffix else None}
    if re.fullmatch(r"\S+\.\d+", value):
        parent, _, suffix = value.rpartition(".")
        return {"name": value, "interface_type": "subinterface", "parent_interface": parent,
                "interface_suffix_vlan_id": int(suffix), "bvi_id": None, "port_channel_id": None, "vlan_id": None}
    kind = "management" if re.match(r"Management", value, re.I) else "physical"
    return {"name": value, "interface_type": kind, "parent_interface": None,
            "interface_suffix_vlan_id": None, "bvi_id": None, "port_channel_id": None, "vlan_id": None}


class InterfaceEvaluator:

    def _parse_interface_block(self, header, lines, i, line_number, line):
        interface = CiscoInterface(name=header["name"], source_context=self._line_contexts.get(line_number))
        for field in ("interface_type", "parent_interface", "interface_suffix_vlan_id", "bvi_id", "port_channel_id", "vlan_id"):
            setattr(interface, field, header[field])
        _mark_explicit(interface, "interface_type", "parent_interface", "interface_suffix_vlan_id", "bvi_id", "port_channel_id", "vlan_id")
        interface.source_attributes.update({"source_line_number": line_number, "raw_header": line})
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
                _mark_explicit(interface, "nameif")
            elif lower == "no nameif":
                interface.nameif = None
                _mark_explicit(interface, "nameif")
                interface.source_attributes.setdefault("negated_commands", []).append(sub)
            elif lower.startswith("security-level "):
                _mark_explicit(interface, "security_level")
                if interface.security_level is not None:
                    interface.source_attributes.setdefault("security_level_history", []).append(interface.security_level)
                try:
                    interface.security_level = int(parts[1])
                except (IndexError, ValueError):
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
            elif lower == "no security-level":
                interface.security_level = None
                _mark_explicit(interface, "security_level")
                interface.source_attributes.setdefault("negated_commands", []).append(sub)
            elif lower.startswith("vlan "):
                _mark_explicit(interface, "vlan_id")
                if len(parts) > 2 and parts[2].lower() == "secondary":
                    _mark_explicit(interface, "secondary_vlan_ids", "secondary_vlan_ranges")
                try:
                    explicit_vlan = int(parts[1])
                    interface.source_attributes["explicit_vlan_id"] = explicit_vlan
                    interface.vlan_id = explicit_vlan
                    if len(parts) > 2 and parts[2].lower() == "secondary":
                        for value in re.split(r"[\s,]+", " ".join(parts[3:]).strip()):
                            value = value.strip()
                            if re.fullmatch(r"\d+", value):
                                interface.secondary_vlan_ids.append(int(value))
                            elif re.fullmatch(r"\d+-\d+", value):
                                interface.secondary_vlan_ranges.append(value)
                            elif value:
                                raise ValueError
                        _mark_explicit(interface, "secondary_vlan_ids", "secondary_vlan_ranges")
                    interface.interface_type = "subinterface"
                except (IndexError, ValueError):
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
            elif lower.startswith("channel-group "):
                _mark_explicit(interface, "channel_group", "channel_group_mode")
                try:
                    interface.channel_group = int(parts[1])
                    interface.channel_group_mode = parts[3] if len(parts) >= 4 and parts[2].lower() == "mode" else None
                    _mark_explicit(interface, "channel_group", "channel_group_mode")
                except (IndexError, ValueError):
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
            elif lower.startswith("member-interface "):
                _mark_explicit(interface, "redundant_interface_members")
                interface.redundant_interface_members.append(parts[1])
                interface.interface_type = "redundant"
            elif lower.startswith("bridge-group "):
                _mark_explicit(interface, "bridge_group")
                try:
                    interface.bridge_group = int(parts[1])
                    if interface.interface_type == "physical":
                        interface.interface_type = "bridge-member"
                except (IndexError, ValueError):
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
            elif lower.startswith("mtu "):
                _mark_explicit(interface, "mtu")
                try:
                    if interface.mtu is not None:
                        interface.source_attributes.setdefault("mtu_history", []).append(interface.mtu)
                    interface.mtu = int(parts[1])
                except (IndexError, ValueError):
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
            elif lower.startswith(("routing-context ", "vrf forwarding ")):
                _mark_explicit(interface, "vrf" if lower.startswith("vrf forwarding ") else "routing_context")
                if len(parts) != 2:
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                    i += 1
                    continue
                _, value = sub.split(maxsplit=1)
                if lower.startswith("vrf forwarding "):
                    interface.vrf = value
                else:
                    interface.routing_context = value
            elif lower.startswith("ip address "):
                _mark_explicit(interface, "ip_mode", "ip", "mask", "standby_ip", "dhcp_setroute")
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
                        interface.raw_extra.setdefault("unmodeled_ip_address_tokens", []).extend(map(sanitize_raw_text, parts[4:]))
            elif lower.startswith("ipv6 address "):
                _mark_explicit(interface, "ipv6_autoconfig", "ipv6_dhcp", "ipv6_dhcp_setroute", "ipv6_addresses")
                args = parts[2:]
                if args and args[0].lower() == "autoconfig":
                    interface.ipv6_autoconfig = True
                    _mark_explicit(interface, "ipv6_autoconfig")
                elif args and args[0].lower() == "dhcp":
                    interface.ipv6_dhcp = True
                    interface.ipv6_dhcp_setroute = "setroute" in {p.lower() for p in args[1:]}
                    _mark_explicit(interface, "ipv6_dhcp", "ipv6_dhcp_setroute")
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
                        _mark_explicit(interface, "ipv6_addresses")
                    except (ValueError, IndexError):
                        interface.extraction_status = "PARSE_ERROR"
                        interface.requires_manual_review = True
                        interface.raw_extra.setdefault("invalid_ipv6_addresses", []).append(sanitize_raw_text(sub))
            elif lower.startswith("tunnel source ") and len(parts) >= 3:
                _mark_explicit(interface, "tunnel_source")
                interface.tunnel_source = " ".join(parts[2:])
            elif lower.startswith("tunnel destination ") and len(parts) >= 3:
                _mark_explicit(interface, "tunnel_destination")
                interface.tunnel_destination = parts[2]
            elif lower.startswith("tunnel protection ipsec profile ") and len(parts) >= 5:
                _mark_explicit(interface, "ipsec_profile")
                interface.ipsec_profile = parts[4]
                interface.source_attributes["route_based_vpn"] = True
                interface.extraction_status = "PARTIAL"
                interface.requires_manual_review = True
            elif lower.startswith("tunnel protection ipsec policy ") and len(parts) >= 5:
                interface.ipsec_policy_acl = parts[4]
                _mark_explicit(interface, "ipsec_policy_acl")
            elif lower.startswith("dhcprelay server "):
                address = parts[2] if len(parts) == 3 else ""
                relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
                if relay is None:
                    relay = CiscoDHCPRelay(name="dhcprelay", extraction_status="PARTIAL", requires_manual_review=False)
                    self.config.dhcp_relays.append(relay)
                if address:
                    entry = CiscoDHCPRelayServer(server=address, interface=interface.name,
                                                 raw=sanitize_raw_text(sub), source_order=i + 1,
                                                 explicit_fields={"server", "interface"})
                    relay.server_entries.append(entry)
                    relay.servers.append(address)
                    relay.server = relay.server or address
                    relay.interface = relay.interface or interface.name
                    try:
                        ipaddress.ip_address(address)
                    except ValueError:
                        relay.extraction_status = "PARSE_ERROR"
                        relay.requires_manual_review = True
                        relay.review_reasons.append("DHCP relay server must be an IP address")
                        self._record_diagnostic(i + 1, sub, "Malformed DHCP relay server", "dhcprelay")
                else:
                    self._record_diagnostic(i + 1, sub, "Malformed DHCP relay server", "dhcprelay")
            elif lower.startswith("dhcprelay information "):
                relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
                if relay is None:
                    relay = CiscoDHCPRelay(name="dhcprelay", extraction_status="PARTIAL", requires_manual_review=False)
                    self.config.dhcp_relays.append(relay)
                relay.options.append(f"{interface.name}: information {' '.join(parts[2:])}")
            elif lower == "management-only":
                interface.management_only = True
                _mark_explicit(interface, "management_only")
            elif lower.startswith("description "):
                interface.description = sub.split(maxsplit=1)[1]
                _mark_explicit(interface, "description")
            elif lower.startswith("policy-route route-map "):
                _mark_explicit(interface, "policy_route_maps")
                parts = sub.split()
                if len(parts) == 3:
                    interface.policy_route_maps.append(parts[2])
                    _mark_explicit(interface, "policy_route_maps")
                else:
                    interface.raw_extra.setdefault("invalid_routing_settings", []).append(sanitize_raw_text(sub))
            elif lower.startswith("policy-route cost "):
                parts = sub.split()
                if len(parts) == 3 and re.fullmatch(r"\d+", parts[2]):
                    interface.policy_route_cost = parts[2]
                    _mark_explicit(interface, "policy_route_cost")
                else:
                    interface.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
            elif lower.startswith("policy-route path-monitoring"):
                parts = sub.split()
                mode = parts[2].lower() if len(parts) == 3 else ""
                known = {"auto", "auto4", "auto6"}
                peer = None
                if len(parts) == 3 and mode not in known:
                    peer = parts[2]
                    mode = "peer"
                if mode:
                    interface.policy_route_path_monitors.append(CiscoPolicyRoutePathMonitor(
                        mode=mode, peer=peer, raw=sanitize_raw_text(sub), source_order=i + 1,
                        explicit_fields={"mode", *(('peer',) if peer else ())},
                    ))
                    _mark_explicit(interface, "policy_route_path_monitors")
                else:
                    interface.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
            elif lower.startswith("zone-member "):
                _mark_explicit(interface, "traffic_zone_members")
                if len(parts) == 2:
                    if parts[1] not in interface.traffic_zone_members:
                        interface.traffic_zone_members.append(parts[1])
                    _mark_explicit(interface, "traffic_zone_members")
                else:
                    interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
            elif lower == "shutdown":
                interface.shutdown = True
                interface.administrative_state = "down"
                _mark_explicit(interface, "shutdown", "administrative_state")
            elif lower == "no shutdown":
                interface.shutdown = False
                interface.administrative_state = "up"
                _mark_explicit(interface, "shutdown", "administrative_state")
            elif lower == "no ip address":
                interface.ip = interface.mask = interface.ip_mode = interface.standby_ip = None
                _mark_explicit(interface, "ip", "mask", "ip_mode", "standby_ip")
                interface.source_attributes.setdefault("negated_commands", []).append(sub)
            else:
                interface.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
            i += 1
        if interface.ip_mode == "static" and normalize_ipv4_network(interface.ip or "", interface.mask or "") is None:
            interface.extraction_status = "PARSE_ERROR"
            interface.requires_manual_review = True
            interface.source_attributes["invalid_ip_address"] = f"{interface.ip or ''} {interface.mask or ''}".strip()
            self._record_diagnostic(line_number, line, "Invalid interface IPv4 address/netmask", "interface", interface.name)
        if interface.raw_extra.get("unmodeled_lines"):
            interface.requires_manual_review = True
            interface.extraction_status = "PARTIAL"
        if interface.dhcp_setroute or interface.ipv6_dhcp_setroute or interface.management_only or interface.ipv6_addresses:
            interface.requires_manual_review = True
            if interface.extraction_status == "EXTRACTED":
                interface.extraction_status = "PARTIAL"
        self.config.interfaces.append(self._with_source_context(interface, line_number))
        return i
