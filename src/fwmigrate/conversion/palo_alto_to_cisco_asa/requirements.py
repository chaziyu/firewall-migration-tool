"""ASA placement proposals remain pending until explicit review."""

from .options import ASAMigrationOptions
from .planning.source_scope import source_scopes, select_source_scope, in_scope
from .planning.topology import device_scope


def build_mapping_requirements(source, derived=None, options=None):
    options = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**(options or {}))
    selected, _ = select_source_scope(source, options.source_scope)
    rows = [{"key": "source_scope", "family": "source", "source_name": "PAN-OS VSYS",
             "value": options.source_scope, "mode": "REQUIRED"}]
    if selected:
        members = {name for zone in source.zones if in_scope(zone, selected) for name in zone.members or ()}
        for interface in source.interfaces:
            if device_scope(interface, selected) and interface.name in members:
                mapping = options.interfaces.get(interface.name)
                rows.append({"key": "interface:" + interface.name, "family": "interface", "source_name": interface.name,
                             "value": mapping, "mode": "REQUIRED"})
    for key, label in (("new_target_confirmed", "Confirm new empty routed single-context target"),
                       ("routing_complete", "Attest complete source connected/static routing evidence")):
        rows.append({"key": key, "family": "design", "source_name": label,
                     "value": getattr(options, key), "mode": "REQUIRED"})
    return {"source_scopes": source_scopes(source), "target": {"vendor": "cisco_asa", "version": "9.20",
            "mode": "routed", "context": "single", "provenance": "PROPOSED_REQUIRES_APPROVAL"}, "decisions": rows}
