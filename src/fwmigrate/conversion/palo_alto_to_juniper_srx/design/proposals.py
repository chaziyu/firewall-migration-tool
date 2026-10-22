"""Pair-owned target placement proposals."""

from collections import Counter
from dataclasses import replace
import re

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity

from ..options import SRXInterfaceMapping, SRXMigrationOptions
from ..requirements import build_mapping_requirements


def build_target_proposals(source, derived, options):
    parsed = options if isinstance(options, SRXMigrationOptions) else SRXMigrationOptions(**(options or {}))
    requested = parsed
    scopes = sorted({pan_scope_identity(row) for row in source.scopes if row.kind == "vsys"})
    if not parsed.source_scope and len(scopes) == 1:
        parsed = replace(parsed, source_scope=scopes[0])
    requirements = build_mapping_requirements(source, derived, parsed)
    interfaces, zones = dict(parsed.interfaces), dict(parsed.zones)
    selected = next((scope for scope in source.scopes if scope.kind == "vsys"
                     and pan_scope_identity(scope) == parsed.source_scope), None)
    if selected and not selected.device_group and not selected.device_serial:
        names = {row["source_name"] for row in requirements["decisions"] if row["family"] == "interface"}
        physical = [row for row in source.interfaces if row.name in names and row.scope
                    and row.scope.device_name == selected.device_name]
        counts = Counter(row.name for row in physical)
        used = {(row.target_interface, row.unit) for row in interfaces.values()}
        for row in sorted(physical, key=lambda row: row.name):
            match = re.fullmatch(r"ethernet1/([1-9]\d*)", row.name or "")
            if row.name in interfaces or counts[row.name] != 1 or not match or row.mode != "layer3" or row.interface_family != "ethernet":
                continue
            mapping = SRXInterfaceMapping(f"ge-0/0/{int(match[1]) - 1}", 0)
            if (mapping.target_interface, 0) not in used:
                interfaces[row.name] = mapping
                used.add((mapping.target_interface, 0))
        units = [row for row in source.interface_units if row.name in names and row.scope
                 and row.scope.device_name == selected.device_name]
        unit_counts = Counter(row.name for row in units)
        for row in sorted(units, key=lambda row: row.name):
            parent = interfaces.get(row.parent)
            if row.name in interfaces or unit_counts[row.name] != 1 or not parent or not str(row.tag).isdigit():
                continue
            tag = int(row.tag)
            if 1 <= tag <= 4094 and (parent.target_interface, tag) not in used:
                interfaces[row.name] = SRXInterfaceMapping(parent.target_interface, tag, tag)
                used.add((parent.target_interface, tag))
        used_zones = set(zones.values())
        for row in requirements["decisions"]:
            name = row["source_name"]
            if row["family"] == "zone" and name not in zones and re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", name) and name not in used_zones:
                zones[name] = name
                used_zones.add(name)
    proposed = replace(parsed, interfaces=interfaces, zones=zones)
    return proposed, [{**row, "evidence_source": "ENGINEER" if (
                         row["key"] == "source_scope" and requested.source_scope
                         or row["family"] == "interface" and row["source_name"] in requested.interfaces
                         or row["family"] == "zone" and row["source_name"] in requested.zones
                       ) else "SOURCE" if row["key"] == "source_scope" and row.get("value")
                       else "ASSUMED_LAYOUT" if row.get("value") else "PENDING",
                       "mode": "SUGGESTED", "review_state": "PENDING"}
                      for row in build_mapping_requirements(source, derived, proposed)["decisions"]]
