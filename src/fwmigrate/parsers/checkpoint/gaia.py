"""Check Point Gaia OS CLI and system configuration parser."""

from __future__ import annotations

import ipaddress
import re
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
        m_if_ip = re.match(r"^set\s+interface\s+([^\s]+)\s+ipv4-address\s+([^\s]+)\s+mask-length\s+(\d+)", line, re.IGNORECASE)
        if m_if_ip:
            if_name = m_if_ip.group(1)
            ip_str = m_if_ip.group(2)
            mask_len = m_if_ip.group(3)
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                prefix = int(mask_len)
                if not 0 <= prefix <= 32:
                    raise ValueError("IPv4 prefix outside 0..32")
                ipaddress.IPv4Address(ip_str)
                if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
                if_data["ips"].append(f"{ip_str}/{prefix}")
            except (ValueError, TypeError) as exc:
                status = ExtractionStatus.PARSE_ERROR
                notes.append(f"invalid-interface-ip:{exc}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_ip",
                source_attributes={"interface": if_name, "ip": ip_str, "mask_length": mask_len},
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
                if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
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
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
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
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
            if_data["description"] = comment
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_comment", source_type="gaia-interface-comment",
                source_attributes={"interface": if_name, "comment": comment},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        m_vlan = re.match(r"^(?:add|set)\s+interface\s+([^\s]+)\s+(?:vlan|vlan-id)\s+(\d+)", line, re.IGNORECASE)
        if m_vlan:
            if_name, vlan_raw = m_vlan.groups()
            vlan_id = int(vlan_raw)
            status = ExtractionStatus.NORMALIZED if 1 <= vlan_id <= 4094 else ExtractionStatus.PARSE_ERROR
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
            if status == ExtractionStatus.NORMALIZED:
                if_data["vlanid"] = vlan_id
                if "." in if_name:
                    if_data["parent"] = if_name.rsplit(".", 1)[0]
            inventory_items.append(SourceInventoryItem(
                domain="gaia", source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_vlan", source_type="gaia-vlan",
                source_attributes={"interface": if_name, "vlan_id": vlan_id}, status=status,
                requires_manual_review=(status == ExtractionStatus.PARSE_ERROR),
                notes=[] if status == ExtractionStatus.NORMALIZED else ["invalid-vlan-id"],
            ))
            continue

        # Interface security zone binding
        m_if_zone = re.match(r"^set\s+interface\s+([^\s]+)\s+security-zone\s+([^\s]+)", line, re.IGNORECASE)
        if m_if_zone:
            if_name = m_if_zone.group(1)
            zone_name = m_if_zone.group(2)
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
            if_data["zone"] = zone_name
            zones_set.add(zone_name)
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/interface/{if_name}/zone",
                name=f"{if_name}_zone_{zone_name}",
                source_attributes={"interface": if_name, "security_zone": zone_name},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        # Static routes
        # e.g. set static-route default nexthop gateway address 192.168.1.1 on
        # e.g. set static-route 10.0.0.0/8 nexthop gateway address 192.168.1.254 on
        m_route = re.match(r"^set\s+static-route\s+([^\s]+)\s+nexthop\s+gateway\s+address\s+([^\s]+)(?:\s+(on|off))?(.*)$", line, re.IGNORECASE)
        if m_route:
            dest_raw = m_route.group(1)
            gw_ip = m_route.group(2)
            state = (m_route.group(3) or "on").lower()
            trailing = (m_route.group(4) or "").strip()
            dest = "0.0.0.0/0" if dest_raw.lower() in ("default", "0.0.0.0/0") else dest_raw
            route_name = f"static_{dest.replace('/', '_')}_{gw_ip}"
            status = ExtractionStatus.NORMALIZED
            notes: List[str] = []
            try:
                ipaddress.ip_network(dest, strict=False)
                ipaddress.ip_address(gw_ip)
                priority_match = re.search(r"(?:^|\s)priority\s+(\d+)(?:\s|$)", trailing, re.IGNORECASE)
                distance_match = re.search(r"(?:^|\s)distance\s+(\d+)(?:\s|$)", trailing, re.IGNORECASE)
                priority = int(priority_match.group(1)) if priority_match else None
                distance = int(distance_match.group(1)) if distance_match else None
                if distance is not None and not 0 <= distance <= 255:
                    raise ValueError("administrative distance outside 0..255")
                recognized_tail = trailing
                recognized_tail = re.sub(r"(?:^|\s)priority\s+\d+(?:\s|$)", " ", recognized_tail, flags=re.IGNORECASE).strip()
                recognized_tail = re.sub(r"(?:^|\s)distance\s+\d+(?:\s|$)", " ", recognized_tail, flags=re.IGNORECASE).strip()
                if recognized_tail:
                    raise ValueError(f"unmodeled route settings: {recognized_tail}")
                if state == "on":
                    routes.append(IRRoute(
                        name=route_name, destination=dest, next_hop=gw_ip,
                        priority=priority, administrative_distance=distance,
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
                source_attributes={"destination": dest, "gateway": gw_ip, "state": state, "trailing": trailing},
                status=status, requires_manual_review=(status == ExtractionStatus.PARSE_ERROR), notes=notes,
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
            interface_type="vlan" if data.get("vlanid") else "physical",
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
