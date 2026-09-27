"""Closed PAN-OS choices for AI help with manual migration decisions."""

from ...vendors.palo_alto.source_model import pan_scope_identity


def _scope(item):
    return getattr(item, "scope", item if hasattr(item, "kind") else None)


def _on_device(item, device):
    scope = _scope(item)
    return bool(scope and (scope.device_serial or scope.device_name) == device)


def _vsys(scope):
    return scope.vsys or (scope.name if scope.kind == "vsys" else None)


def _options(items, *, evidence):
    candidates = []
    for item in items:
        name, scope = getattr(item, "name", None), _scope(item)
        if not name or not scope:
            continue
        strong, supporting = evidence(item, scope)
        candidates.append({"value": name, "target_scope": pan_scope_identity(scope),
            "strong_evidence": list(strong), "supporting_evidence": list(supporting), "contradictions": []})
    scopes = {}
    for option in candidates:
        scopes.setdefault(option["value"], set()).add(option["target_scope"])
    ambiguous = {name for name, identities in scopes.items() if len(identities) > 1}
    return [item for item in candidates if item["value"] not in ambiguous]


def _interface_compatible(source_facts, interface):
    explicit = source_facts.get("source_explicit", {})
    source_type = str(explicit.get("type") or ("vlan" if explicit.get("vlanid") is not None else "")).casefold()
    family = str(getattr(interface, "interface_family", "") or "").casefold()
    name = str(getattr(interface, "name", "") or "").casefold()
    if source_type in {"tunnel", "ipsec", "gre"}:
        return family == "tunnel"
    if source_type == "aggregate":
        return family == "aggregate-ethernet"
    if source_type == "loopback":
        return family == "loopback"
    if source_type == "vlan":
        tag = explicit.get("vlanid")
        return (tag is not None and str(tag) == str(getattr(interface, "tag", None))
                and ((family == "ethernet" and "." in name) or family == "vlan"))
    return source_type == "physical" and family == "ethernet"


def build_ai_selection_options(source, derived, decisions, target, device, review_evidence):
    """Build advisory choices solely from explicit PAN objects and source evidence."""
    result = {}
    if target is None or not device:
        return result
    config = target.config
    device_scopes = [scope for scope in getattr(config, "scopes", ())
                     if (scope.device_serial or scope.device_name) == device]
    device_vsys = {name for scope in device_scopes if (name := _vsys(scope))}
    topology = {(item.scope, item.interface): item for item in
                getattr(getattr(target, "derived", None), "interface_topology", ())}
    mapped_interfaces = {(item.source_vdom, item.source_name): item.value for item in decisions.decisions
                         if item.target_field == "target_interface" and item.value}
    for decision in decisions.decisions:
        if decision.review_state.value != "PENDING" or decision.mode.value in {"AUTO", "UNSUPPORTED"}:
            continue
        evidence = review_evidence.get(decision.key, {})
        if decision.target_field == "vsys":
            options = _options((scope for scope in device_scopes if scope.kind == "vsys"),
                evidence=lambda item, scope: (("Explicit VSYS on selected target device",), ()))
        elif decision.target_field == "virtual_router":
            related = {router for (vdom, _), name in mapped_interfaces.items() if vdom == decision.source_vdom
                       for (scope, interface), topo in topology.items() if interface == name
                       for router in getattr(topo, "virtual_routers", ())}
            options = _options((item for item in config.virtual_routers if _on_device(item, device)),
                evidence=lambda item, scope: (("Explicit virtual router on selected target device",),
                    ((f"Target VSYS: {_vsys(scope)}",) if _vsys(scope) else ())))
            if related:
                options = [item for item in options if item["value"] in related]
        elif decision.target_field == "target_zone":
            assigned_vsys = next((item.value for item in decisions.decisions
                if item.source_vdom == decision.source_vdom and item.target_field == "vsys" and item.value), None)
            compatible_vsys = assigned_vsys or (next(iter(device_vsys)) if len(device_vsys) == 1 else None)
            if compatible_vsys:
                mapped_name = mapped_interfaces.get((decision.source_vdom, decision.source_name))
                assigned_zones = {zone for (scope, interface), topo in topology.items()
                                  if interface == mapped_name for zone in getattr(topo, "zones", ())}
                options = _options((item for item in config.zones if _on_device(item, device)
                    and _vsys(_scope(item)) == compatible_vsys),
                    evidence=lambda item, scope: ((f"Explicit PAN zone in VSYS {compatible_vsys}",), ()))
                if assigned_zones:
                    options = [item for item in options if item["value"] in assigned_zones]
            else:
                options = []
        elif decision.target_field == "target_interface":
            assigned_vsys = next((item.value for item in decisions.decisions
                if item.source_vdom == decision.source_vdom and item.target_field == "vsys" and item.value), None)
            compatible_vsys = assigned_vsys or (next(iter(device_vsys)) if len(device_vsys) == 1 else None)
            source_facts = review_evidence.get((decision.source_vdom, decision.source_name), {})
            source_parent = source_facts.get("source_explicit", {}).get("interface")
            mapped_parent = mapped_interfaces.get((decision.source_vdom, source_parent)) if source_parent else None
            items = (*config.interfaces, *config.interface_units)
            options = _options((item for item in items if compatible_vsys and _on_device(item, device)
                and (compatible_vsys in getattr(topology.get((pan_scope_identity(_scope(item)), item.name)),
                    "imported_vsys", ()) if topology else _vsys(_scope(item)) == compatible_vsys)
                and (not mapped_parent or getattr(item, "parent", None) == mapped_parent)
                and _interface_compatible(source_facts, item)),
                evidence=lambda item, scope: (("Explicit structurally compatible PAN interface",),
                    ((f"Target VSYS: {_vsys(scope)}",) if _vsys(scope) else ())))
        else:
            continue
        if options:
            result[decision.key] = options
    return result
