"""Check Point Gaia OS CLI and system configuration parser."""

from __future__ import annotations

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
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
            if_data["ips"].append(f"{ip_str}/{mask_len}")
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/interface/{if_name}",
                name=f"{if_name}_ip",
                source_attributes={"interface": if_name, "ip": ip_str, "mask_length": mask_len},
                status=ExtractionStatus.NORMALIZED,
            ))
            continue

        # Interface state
        m_if_state = re.match(r"^set\s+interface\s+([^\s]+)\s+state\s+(on|off)", line, re.IGNORECASE)
        if m_if_state:
            if_name = m_if_state.group(1)
            state = m_if_state.group(2).lower()
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
            if_data["enabled"] = (state == "on")
            continue

        # Interface comment
        m_if_comm = re.match(r'^set\s+interface\s+([^\s]+)\s+comments?\s+"?([^"]*)"?', line, re.IGNORECASE)
        if m_if_comm:
            if_name = m_if_comm.group(1)
            comment = m_if_comm.group(2)
            if_data = interfaces_dict.setdefault(if_name, {"name": if_name, "ips": [], "enabled": True})
            if_data["description"] = comment
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
        m_route = re.match(r"^set\s+static-route\s+([^\s]+)\s+nexthop\s+gateway\s+address\s+([^\s]+)", line, re.IGNORECASE)
        if m_route:
            dest_raw = m_route.group(1)
            gw_ip = m_route.group(2)
            dest = "0.0.0.0/0" if dest_raw.lower() in ("default", "0.0.0.0/0") else dest_raw
            route_name = f"static_{dest.replace('/', '_')}_{gw_ip}"

            routes.append(IRRoute(
                name=route_name,
                destination=dest,
                next_hop=gw_ip,
            ))
            inventory_items.append(SourceInventoryItem(
                domain="gaia",
                source_path=f"{src_path}/routing",
                name=route_name,
                source_attributes={"destination": dest, "gateway": gw_ip},
                status=ExtractionStatus.NORMALIZED,
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
        ir_interfaces.append(IRInterface(
            name=if_name,
            interface_type="physical",
            status=data.get("enabled", True),
            ip=data["ips"][0] if data.get("ips") else None,
            zone=data.get("zone"),
            description=data.get("description"),
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
