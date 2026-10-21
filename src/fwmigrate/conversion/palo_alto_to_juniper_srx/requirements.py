"""Explicit PAN-OS source and Junos placement requirements."""

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def build_mapping_requirements(source, derived=None, options=None):
    options = options or {}
    scopes = sorted({pan_scope_identity(row) for row in source.scopes if row.kind == "vsys"})
    requirements = [{"key": "source_scope", "family": "source", "source_name": "PAN-OS VSYS",
                     "value": options.source_scope, "choices": scopes, "mode": "REQUIRED"}]
    selected = next((scope for scope in source.scopes if scope.kind == "vsys"
                     and pan_scope_identity(scope) == options.source_scope), None)
    member_names = {name for zone in source.zones if selected and zone.scope
                    and pan_scope_identity(zone.scope) == pan_scope_identity(selected)
                    for name in (zone.members or ())}
    unit_parents = {row.parent for row in source.interface_units if row.name in member_names and row.parent}
    member_names.update(unit_parents)
    for interface in source.interfaces:
        if (interface.scope and interface.scope.kind == "device" and selected
                and (interface.scope.device_serial or interface.scope.device_name)
                == (selected.device_serial or selected.device_name) and interface.name in member_names):
            value = options.interfaces.get(interface.name) if hasattr(options, "interfaces") else options.get("interfaces", {}).get(interface.name)
            requirements.append({"key": f"interface:{pan_scope_identity(interface.scope)}:{interface.name}",
                                 "family": "interface", "source_name": interface.name, "value": value,
                                 "mode": "REQUIRED"})
    selected_scope = options.source_scope if hasattr(options, "source_scope") else options.get("source_scope")
    for zone in source.zones:
        if not zone.scope or zone.scope.kind != "vsys" or pan_scope_identity(zone.scope) != selected_scope:
            continue
        zones = options.zones if hasattr(options, "zones") else options.get("zones", {})
        requirements.append({"key": f"zone:{pan_scope_identity(zone.scope)}:{zone.name}",
                             "family": "zone", "source_name": zone.name,
                             "value": zones.get(zone.name), "mode": "REQUIRED"})
    for unit in source.interface_units:
        same_scope = bool(unit.scope and selected and (
            pan_scope_identity(unit.scope) == pan_scope_identity(selected) or
            (unit.scope.kind == "device" and (unit.scope.device_serial or unit.scope.device_name)
             == (selected.device_serial or selected.device_name))))
        if same_scope and unit.name in member_names:
            interfaces = options.interfaces if hasattr(options, "interfaces") else options.get("interfaces", {})
            requirements.append({"key": f"interface:{pan_scope_identity(unit.scope)}:{unit.name}",
                                 "family": "interface", "source_name": unit.name,
                                 "value": interfaces.get(unit.name), "mode": "REQUIRED"})
    return {"source_scopes": scopes, "target": {"vendor": "juniper_srx", "version": "25.2R1",
            "mode": "standalone", "context": "root"}, "decisions": requirements}
