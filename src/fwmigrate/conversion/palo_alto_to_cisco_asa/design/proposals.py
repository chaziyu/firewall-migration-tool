"""Pair-owned target placement proposals."""

from dataclasses import asdict

from ..options import ASAMigrationOptions
from ..requirements import build_mapping_requirements


def build_target_proposals(source, derived, options):
    parsed = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**(options or {}))
    requirements = build_mapping_requirements(source, derived, parsed)
    return parsed, [{**row, "evidence_source": "ENGINEER" if row.get("value") else "PENDING"}
                    for row in requirements["decisions"]]
