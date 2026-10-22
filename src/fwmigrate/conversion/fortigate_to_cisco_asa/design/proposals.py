"""Offline ASA naming proposals; security levels remain explicit decisions."""

from dataclasses import replace
import re

from ..options import ASAMigrationOptions
from ..requirements import source_vdoms


def build_target_proposals(source, options):
    parsed = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**options)
    scopes = source_vdoms(source)
    parsed = replace(parsed, source_vdom=parsed.source_vdom or (scopes[0] if len(scopes) == 1 else None),
                     target_context=parsed.target_context or "single", target_version=parsed.target_version or "9.20",
                     target_mode=parsed.target_mode or "routed")
    proposals = []
    mappings = parsed.interfaces.get(parsed.source_vdom, {})
    used_ports = {row.interface.casefold() for row in mappings.values()}
    used_names = {row.nameif.casefold() for row in mappings.values()}
    for row in sorted(source.interfaces, key=lambda row: row.name):
        if (row.vdom or "root") != parsed.source_vdom or row.name in mappings or row.type not in {"physical", "ethernet"}:
            continue
        match = re.fullmatch(r"port([1-9]\d*)", row.name)
        if not match:
            continue
        port = f"GigabitEthernet0/{match[1]}"
        if port.casefold() in used_ports or row.name.casefold() in used_names:
            continue
        proposals.append({"source_vdom": parsed.source_vdom, "source_name": row.name,
                          "value": {"interface": port, "nameif": row.name},
                          "mode": "SUGGESTED", "review_state": "PENDING", "evidence_source": "ASSUMED_LAYOUT"})
        used_ports.add(port.casefold())
        used_names.add(row.name.casefold())
    return parsed, proposals
