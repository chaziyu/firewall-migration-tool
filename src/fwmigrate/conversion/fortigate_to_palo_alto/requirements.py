"""Explicit target mappings needed by the FortiGate to PAN-OS planner."""


def build_mapping_requirements(config, derived):
    references = getattr(derived, "references", None)
    reference_objects = getattr(references, "objects", {})
    interface_refs = reference_objects.get("interface", {})
    zone_refs = reference_objects.get("zone", {})
    vdoms = sorted({
        getattr(item, "vdom", None) or "root"
        for field in ("interfaces", "addresses", "address_groups", "policies", "zones", "static_routes")
        for item in getattr(config, field, ())
    } or {"root"})
    vdoms = sorted(set(vdoms) | {
        vdom for bucket in reference_objects.values() for vdom, _ in bucket
    })
    interfaces = sorted({item.name for item in getattr(config, "interfaces", ()) if item.name} | {name for _, name in interface_refs})
    zones = sorted({item.name for item in getattr(config, "zones", ()) if item.name} | {name for _, name in zone_refs})
    policy_interface_refs = set()
    for policy in getattr(config, "policies", ()):
        policy_interface_refs.update((*getattr(policy, "srcintf", ()), *getattr(policy, "dstintf", ())))
    known_interfaces = set(interfaces)
    return {
        "vdoms": [{"source_vdom": name, "requires": ["vsys", "virtual_router"]} for name in vdoms],
        "interfaces": [{"source_interface": name, "is_interface": name in known_interfaces, "requires": ["target_zone", *( ["target_interface"] if name in known_interfaces else [])]} for name in sorted(known_interfaces | policy_interface_refs | set(zones))],
        "zones": [{"source_zone": name, "requires": ["target_zone"]} for name in zones],
        "policy_interface_references": sorted(policy_interface_refs),
        "topology_issues": [
            {"source_vdom": item.vdom, "source_interface": item.name, "issues": list(item.issues)}
            for item in getattr(getattr(derived, "topology", None), "interfaces", ()) if item.issues
        ],
    }
