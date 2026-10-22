"""Pair-owned target placement proposals."""

from dataclasses import asdict, replace
import re

from ..options import ASAMigrationOptions
from ..requirements import build_mapping_requirements
from ..planning.source_scope import source_scopes


def build_target_proposals(source, derived, options):
    parsed = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**(options or {}))
    requested = parsed
    scopes = source_scopes(source)
    if not parsed.source_scope and len(scopes) == 1:
        parsed = replace(parsed, source_scope=scopes[0])
    requirements = build_mapping_requirements(source, derived, parsed)
    proposals = []
    used_ports = {row.target_interface.casefold() for row in parsed.interfaces.values()}
    used_names = {row.nameif.casefold() for row in parsed.interfaces.values()}
    for row in requirements["decisions"]:
        value = asdict(row["value"]) if row["family"] == "interface" and row.get("value") else row.get("value")
        match = re.fullmatch(r"ethernet1/([1-9]\d*)", row["source_name"])
        if row["family"] == "interface" and not value and match:
            port, nameif = f"GigabitEthernet0/{match[1]}", f"ethernet1_{match[1]}"
            if port.casefold() not in used_ports and nameif.casefold() not in used_names:
                value = {"target_interface": port, "nameif": nameif}
                used_ports.add(port.casefold())
                used_names.add(nameif.casefold())
        origin = "ENGINEER" if (
            row["key"] == "source_scope" and requested.source_scope
            or row["family"] == "interface" and row["source_name"] in requested.interfaces
            or row["family"] == "design" and row.get("value")
        ) else "SOURCE" if row["key"] == "source_scope" and value else "ASSUMED_LAYOUT" if value else "PENDING"
        proposals.append({**row, "value": value, "evidence_source": origin,
                          "mode": "SUGGESTED", "review_state": "PENDING"})
    return parsed, proposals
