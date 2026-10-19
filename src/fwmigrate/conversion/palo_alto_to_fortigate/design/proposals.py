"""Deterministic FortiGate target intent; proposals never grant approval."""
from copy import deepcopy
import re

from ..options import FGMigrationOptions
from ..planning.naming import allocate_plan_names
from ..planning.source_scope import identity, in_scope, select_source_scope, source_scopes


def build_target_proposals(source, derived, options, evidence=None):
    requested = options if isinstance(options, FGMigrationOptions) else FGMigrationOptions(**(options or {}))
    values = deepcopy(requested.to_dict())
    proposals = []

    def propose(key, value, reason, origin="DERIVED"):
        proposals.append({"key": key, "value": value, "reason": reason, "evidence_source": origin,
                          "mode": "SUGGESTED", "review_state": "PENDING"})
        return value

    scopes = source_scopes(source)
    if not values["source_scope"] and len(scopes) == 1:
        values["source_scope"] = propose("source_scope", scopes[0], "Only source device/VSYS; managed inheritance remains unsupported.", "SOURCE")
    scope, _ = select_source_scope(source, FGMigrationOptions(**values))
    if scope is None:
        return FGMigrationOptions(**values), proposals
    records = evidence["records"] if evidence else ()
    if not values["vdom"]:
        vdoms = sorted({r.vdom for r in records if r.source_path == "system settings" and r.vdom})
        if len(vdoms) == 1:
            values["vdom"] = propose("vdom", vdoms[0], "One destination VDOM has explicit settings.", "TARGET")
        elif evidence is None:
            values["vdom"] = propose("vdom", "root", "Proposed offline root VDOM; confirm target ownership.")
    profile = values["profile"]
    baseline = {"fortios_version": "7.4.6", "operating_mode": "nat", "ngfw_mode": "profile-based"}
    settings = [r for r in records if r.source_path == "system settings" and r.vdom == values["vdom"]]
    globals_ = [r for r in records if r.source_path == "system global"]
    observed = {"fortios_version": evidence["version"]} if evidence else {}
    if len(settings) == 1:
        observed.update({"operating_mode": settings[0].values.get("opmode"), "ngfw_mode": settings[0].values.get("ngfw-mode"),
                         "nat_mode": {"enable": "central", "disable": "policy"}.get(settings[0].values.get("central-nat"))})
    if len(globals_) == 1:
        observed["vdom_mode"] = {"no-vdom": "single", "multi-vdom": "multi"}.get(globals_[0].values.get("vdom-mode"))
    if evidence is None:
        baseline.update({"nat_mode": "central", "vdom_mode": "single" if values["vdom"] == "root" else "multi"})
    for field in (*baseline, "nat_mode", "vdom_mode"):
        if profile.get(field):
            continue
        value = observed.get(field) or baseline.get(field)
        if value:
            profile[field] = propose("profile:" + field, value,
                                     "Explicit destination setting." if observed.get(field) else "Proposed supported command baseline; device modes are not changed.",
                                     "TARGET" if observed.get(field) else "DERIVED")
    if "ports" not in profile and evidence and not evidence["validation_errors"]:
        ports = []
        for r in records:
            if (r.source_path == "system interface" and r.object_name and r.values.get("type") == "physical"
                    and str(r.values.get("ip", "")) == "0.0.0.0 0.0.0.0"
                    and r.values.get("vdom") == values["vdom"]
                    and (r.cli_scope, r.vdom, r.source_path, r.object_name) not in evidence["duplicates"]
                    and not any(r.object_name in str(other.values) for other in records if other is not r)):
                ports.append(r.object_name)
        if ports:
            profile["ports"] = propose("profile:ports", sorted(set(ports)), "Explicit unaddressed, unreferenced physical ports; inventory may be incomplete.", "TARGET")
    ports = profile.get("ports", [])
    names = {name for zone in source.zones if in_scope(zone, scope) for name in zone.members or ()}
    names.update(name for item in source.interface_imports if in_scope(item, scope) for name in item.interfaces or ())
    interfaces = [item for item in (*source.interfaces, *source.interface_units)
                  if item.scope and item.scope.device_name == scope.device_name]
    names.update(item.parent for item in interfaces if item.name in names and getattr(item, "parent", None))
    used = set(values["interfaces"].values()) | set(values["zones"].values())
    pool = sorted(set(ports) - used, key=lambda name: tuple((0, int(part)) if part.isdigit() else (1, part) for part in re.split(r"(\d+)", name)))
    selected = sorted((item for item in interfaces if item.name in names), key=lambda item: item.name)
    for item in selected:
        if item.name in values["interfaces"] or item.interface_family != "ethernet" or getattr(item, "parent", None) or item.mode != "layer3":
            continue
        if pool:
            port = pool.pop(0)
            values["interfaces"][item.name] = propose("interfaces:" + item.name, port, "Proposed port allocation from declared inventory; confirm cabling.")
            used.add(port)
    units = [item for item in selected if item.interface_family == "ethernet" and getattr(item, "parent", None)
             and item.parent in values["interfaces"] and str(item.tag or "").isdigit() and 1 <= int(item.tag) <= 4094]
    for item in units:
        if item.name in values["interfaces"]:
            continue
        candidate = f"{values['interfaces'][item.parent]}.{item.tag}"
        if len(candidate) > 15 or candidate in used or candidate in ports:
            candidate = allocate_plan_names([item], "interface", reserved=used | set(ports) | {"any"}, limit=15)[identity(item, "interface")]
        values["interfaces"][item.name] = propose("interfaces:" + item.name, candidate, "Proposed VLAN interface using the mapped parent and explicit source tag.")
        used.add(candidate)
    zones = [item for item in source.zones if in_scope(item, scope) and item.network_type == "layer3"]
    reserved = {zone.name for zone in zones if zone.name and zone.name.casefold() in {"any", "all"}}
    zone_names = allocate_plan_names(zones, "zone", reserved=used | set(ports) | reserved, limit=35)
    for zone in zones:
        if zone.name not in values["zones"]:
            values["zones"][zone.name] = propose("zones:" + zone.name, zone_names[identity(zone, "zone")], "Proposed target name from the explicit source zone.", "SOURCE")
    routers = [r for r in source.virtual_routers if r.scope and r.scope.device_name == scope.device_name]
    if len(routers) == 1 and routers[0].name not in values["routers"]:
        values["routers"][routers[0].name] = propose("routers:" + routers[0].name, 0, "Proposed VRF 0 for the sole source virtual router; no routing domains are merged.")
    return FGMigrationOptions(**values), proposals
