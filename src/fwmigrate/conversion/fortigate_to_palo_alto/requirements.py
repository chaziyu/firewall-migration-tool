"""Explicit target mappings needed by the FortiGate to PAN-OS planner."""


def build_mapping_requirements(config, derived):
    required = {}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(config, "zones", ())}

    def need(vdom, name, kind, reason, consumer, *fields):
        if not name:
            return
        key = (vdom or "root", name)
        item = required.setdefault(key, {
            "source_vdom": key[0], "source_name": name, "kind": kind,
            "requires": [], "reasons": [], "_affected": {},
        })
        item["requires"] = list(dict.fromkeys([*item["requires"], *fields]))
        item["reasons"] = list(dict.fromkeys([*item["reasons"], reason]))
        item["_affected"].setdefault(reason, set()).add(consumer)

    for policy_index, policy in enumerate(getattr(config, "policies", ())):
        vdom = policy.vdom or "root"
        identity = policy.policy_id if policy.policy_id is not None else policy.name or policy_index
        consumer = ("security_policy", vdom, identity)
        for name in (*getattr(policy, "srcintf", ()), *getattr(policy, "dstintf", ())):
            kind = "zone" if (vdom, name) in zone_names else "interface"
            fields = ("target_zone", "target_interface") if kind == "interface" else ("target_zone",)
            need(vdom, name, kind, "security_policy", consumer, *fields)
            if kind == "zone":
                zone = next(item for item in config.zones if (item.vdom or "root", item.name) == (vdom, name))
                for member in zone.members or ():
                    need(vdom, member, "interface", "zone_membership", ("zone_membership", vdom, name), "target_interface")
            for zone in getattr(config, "zones", ()):
                if (zone.vdom or "root") == vdom and name in (zone.members or ()):
                    need(vdom, zone.name, "zone", "security_policy", consumer, "target_zone")
                    for member in zone.members or ():
                        need(vdom, member, "interface", "zone_membership", ("zone_membership", vdom, zone.name), "target_interface")
    for route_index, route in enumerate(getattr(config, "static_routes", ())):
        if route.device:
            identity = route.seq_num if route.seq_num is not None else route_index
            need(route.vdom, route.device, "interface", "static_route", ("static_route", route.vdom or "root", identity), "target_interface", "target_zone")
    policies = {(item.vdom or "root", item.policy_id): item for item in getattr(config, "policies", ())}
    for nat in getattr(derived, "nat", ()):
        vdom = getattr(nat, "vdom", None) or "root"
        if len(getattr(nat, "egress_interfaces", ())) == 1 and len(getattr(nat, "translated_addresses", ())) == 1:
            policy = policies.get((vdom, nat.policy_id))
            if policy:
                consumer = ("source_nat", vdom, nat.policy_id)
                for name in (*policy.srcintf, *nat.egress_interfaces):
                    need(vdom, name, "interface", "source_nat", consumer, "target_zone")
                need(vdom, nat.egress_interfaces[0], "interface", "source_nat", consumer, "target_interface")

    vdoms = sorted({vdom for vdom, _ in required} | {getattr(item, "vdom", None) or "root" for item in getattr(config, "static_routes", ())} | {getattr(item, "vdom", None) or "root" for item in getattr(config, "policies", ())} or {"root"})
    interfaces = []
    for _, value in sorted(required.items()):
        item = {key: val for key, val in value.items() if key != "_affected"}
        item["affected_by"] = {category: len(consumers) for category, consumers in sorted(value["_affected"].items())}
        item["affected_count"] = sum(item["affected_by"].values())
        item["reference_count"] = item["affected_count"]
        item["source_interface"] = value["source_name"]
        item["is_interface"] = value["kind"] == "interface"
        interfaces.append(item)
    zones = [{"source_vdom": vdom, "source_zone": name, "requires": ["target_zone"]}
             for (vdom, name), item in sorted(required.items()) if item["kind"] == "zone"]
    required_keys = set(required)
    optional = [{"source_vdom": item.vdom or "root", "source_name": item.name, "kind": "interface"}
                for item in getattr(config, "interfaces", ())
                if item.name and (item.vdom or "root", item.name) not in required_keys]
    optional.extend({"source_vdom": item.vdom or "root", "source_name": item.name, "kind": "zone"}
                    for item in getattr(config, "zones", ())
                    if item.name and (item.vdom or "root", item.name) not in required_keys)
    return {"vdoms": [{"source_vdom": name, "requires": ["vsys", "virtual_router"]} for name in vdoms],
            "interfaces": interfaces, "zones": zones,
            "required_zones": [item["source_zone"] for item in zones],
            "required_zone_keys": [(item["source_vdom"], item["source_zone"]) for item in zones],
            "policy_interface_references": sorted({name for policy in getattr(config, "policies", ()) for name in (*policy.srcintf, *policy.dstintf)}),
            "optional": optional, "topology_issues": []}
