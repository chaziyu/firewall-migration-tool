"""Explicit target mappings needed by the FortiGate to PAN-OS planner."""


def build_mapping_requirements(config, derived):
    required = {}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(config, "zones", ())}

    def need(vdom, name, kind, reason, *fields):
        if not name:
            return
        key = (vdom or "root", name)
        item = required.setdefault(key, {"source_vdom": key[0], "source_name": name,
            "kind": kind, "requires": [], "reasons": [], "reference_count": 0})
        item["requires"] = list(dict.fromkeys([*item["requires"], *fields]))
        item["reasons"] = list(dict.fromkeys([*item["reasons"], reason]))
        item["reference_count"] += 1

    for policy in getattr(config, "policies", ()):
        for name in (*getattr(policy, "srcintf", ()), *getattr(policy, "dstintf", ())):
            kind = "zone" if ((policy.vdom or "root", name) in zone_names) else "interface"
            need(policy.vdom, name, kind, "security_policy", "target_zone")
            if kind == "zone":
                zone = next(item for item in config.zones if (item.vdom or "root", item.name) == (policy.vdom or "root", name))
                for member in zone.members or ():
                    need(policy.vdom, member, "interface", "zone_membership", "target_interface")
            for zone in getattr(config, "zones", ()):
                if (zone.vdom or "root") == (policy.vdom or "root") and name in (zone.members or ()):
                    need(zone.vdom, zone.name, "zone", "security_policy", "target_zone")
                    for member in zone.members or ():
                        need(zone.vdom, member, "interface", "zone_membership", "target_interface")
    for route in getattr(config, "static_routes", ()):
        if route.device:
            need(route.vdom, route.device, "interface", "static_route", "target_interface", "target_zone")
    policies = {item.policy_id: item for item in getattr(config, "policies", ())}
    for nat in getattr(derived, "nat", ()):
        if len(getattr(nat, "egress_interfaces", ())) == 1 and len(getattr(nat, "translated_addresses", ())) == 1:
            policy = policies.get(nat.policy_id)
            if policy:
                for name in (*policy.srcintf, *nat.egress_interfaces):
                    need(policy.vdom, name, "interface", "source_nat", "target_zone")
                need(policy.vdom, nat.egress_interfaces[0], "interface", "source_nat", "target_interface")
    vdoms = sorted({vdom for vdom, _ in required} | {getattr(item, "vdom", None) or "root" for item in getattr(config, "static_routes", ())} | {getattr(item, "vdom", None) or "root" for item in getattr(config, "policies", ())} or {"root"})
    interfaces = [dict(value, source_interface=value["source_name"], is_interface=value["kind"] == "interface")
                  for _, value in sorted(required.items())]
    zones = [{"source_vdom": vdom, "source_zone": name, "requires": ["target_zone"]}
             for (vdom, name), item in sorted(required.items()) if item["kind"] == "zone"]
    optional = [{"source_vdom": item.vdom or "root", "source_name": item.name, "kind": "interface"}
                for item in getattr(config, "interfaces", ())
                if item.name and (item.vdom or "root", item.name) not in required]
    optional.extend({"source_vdom": item.vdom or "root", "source_name": item.name, "kind": "zone"}
                    for item in getattr(config, "zones", ())
                    if item.name and (item.vdom or "root", item.name) not in required)
    return {"vdoms": [{"source_vdom": name, "requires": ["vsys", "virtual_router"]} for name in vdoms],
            "interfaces": interfaces, "zones": zones,
            "required_zones": [item["source_zone"] for item in zones],
            "required_zone_keys": [(item["source_vdom"], item["source_zone"]) for item in zones],
            "policy_interface_references": sorted({name for policy in getattr(config, "policies", ()) for name in (*policy.srcintf, *policy.dstintf)}),
            "optional": optional, "topology_issues": []}
