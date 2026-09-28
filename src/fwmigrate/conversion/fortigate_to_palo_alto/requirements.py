"""Explicit target mappings needed by the FortiGate to PAN-OS planner."""


def build_mapping_requirements(config, derived):
    """Return only mappings consumed by the currently implemented planner.

    Recommendation-only source families do not create blocking mapping
    requirements. A target decision becomes required when a planned item
    actually consumes that target field.
    """
    required = {}
    required_vdom_fields = {}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(config, "zones", ())}

    def need_vdom(vdom, *fields):
        vdom = vdom or "root"
        values = required_vdom_fields.setdefault(vdom, [])
        required_vdom_fields[vdom] = list(dict.fromkeys([*values, *fields]))

    def need(vdom, name, kind, reason, consumer, *fields):
        if not name:
            return
        if "target_interface" in fields:
            # Executable interface planning consumes explicit VSYS import and
            # virtual-router ownership for every mapped target interface.
            need_vdom(vdom, "vsys", "virtual_router")
        key = (vdom or "root", name, kind)
        item = required.setdefault(key, {
            "source_vdom": key[0], "source_name": name, "kind": kind,
            "requires": [], "reasons": [], "_affected": {},
        })
        item["requires"] = list(dict.fromkeys([*item["requires"], *fields]))
        item["reasons"] = list(dict.fromkeys([*item["reasons"], reason]))
        item["_affected"].setdefault(reason, set()).add(consumer)

    # VSYS-scoped families that the planner currently produces directly.
    for section in ("addresses", "address_groups", "recurring_schedules", "one_time_schedules"):
        for item in getattr(config, section, ()):
            need_vdom(getattr(item, "vdom", None), "vsys")
    service_views = getattr(derived, "services", None)
    for item in (*getattr(service_views, "services", ()), *getattr(service_views, "groups", ())):
        need_vdom(getattr(item, "vdom", None), "vsys")

    for policy_index, policy in enumerate(getattr(config, "policies", ())):
        vdom = policy.vdom or "root"
        need_vdom(vdom, "vsys")
        identity = policy.policy_id if policy.policy_id is not None else policy.name or policy_index
        consumer = ("security_policy", vdom, identity)
        for name in (*(getattr(policy, "srcintf", None) or ()), *(getattr(policy, "dstintf", None) or ())):
            kind = "zone" if (vdom, name) in zone_names else "interface"
            # Security rules consume zones. A source zone additionally produces a
            # PlannedZone, which consumes mappings for each explicit member.
            need(vdom, name, kind, "security_policy", consumer, "target_zone")
            if kind == "zone":
                zone = next(item for item in config.zones if (item.vdom or "root", item.name) == (vdom, name))
                for member in zone.members or ():
                    need(vdom, member, "interface", "zone_membership",
                         ("zone_membership", vdom, name), "target_interface")

    for route_index, route in enumerate(getattr(config, "static_routes", ())):
        vdom = route.vdom or "root"
        need_vdom(vdom, "virtual_router")
        if route.device:
            identity = route.seq_num if route.seq_num is not None else route_index
            need(vdom, route.device, "interface", "static_route",
                 ("static_route", vdom, identity), "target_interface")

    policies = {(item.vdom or "root", item.policy_id): item for item in getattr(config, "policies", ())}
    for nat in getattr(derived, "nat", ()):
        vdom = getattr(nat, "vdom", None) or "root"
        need_vdom(vdom, "vsys")
        if len(getattr(nat, "egress_interfaces", ())) == 1 and len(getattr(nat, "translated_addresses", ())) == 1:
            policy = policies.get((vdom, nat.policy_id))
            if policy:
                consumer = ("source_nat", vdom, nat.policy_id)
                for name in (*(policy.srcintf or ()), *nat.egress_interfaces):
                    kind = "zone" if (vdom, name) in zone_names else "interface"
                    need(vdom, name, kind, "source_nat", consumer, "target_zone")
                    if kind == "zone":
                        zone = next(item for item in config.zones
                                    if (item.vdom or "root", item.name) == (vdom, name))
                        for member in zone.members or ():
                            need(vdom, member, "interface", "zone_membership",
                                 ("zone_membership", vdom, name), "target_interface")
                egress = nat.egress_interfaces[0]
                if (vdom, egress) not in zone_names:
                    need(vdom, egress, "interface", "source_nat", consumer, "target_interface")

    for vip in getattr(config, "vips", ()):
        vdom = vip.vdom or "root"
        consumers = [policy for policy in getattr(config, "policies", ())
                     if (policy.vdom or "root") == vdom and vip.name in (policy.dstaddr or ())]
        if consumers:
            need_vdom(vdom, "vsys")
        for policy in consumers:
            consumer = ("vip", vdom, vip.name)
            for name in policy.srcintf or ():
                kind = "zone" if (vdom, name) in zone_names else "interface"
                need(vdom, name, kind, "vip", consumer, "target_zone")
                if kind == "zone":
                    zone = next(item for item in config.zones
                                if (item.vdom or "root", item.name) == (vdom, name))
                    for member in zone.members or ():
                        need(vdom, member, "interface", "zone_membership",
                             ("zone_membership", vdom, name), "target_interface")
            if vip.extintf and vip.extintf != "any":
                kind = "zone" if (vdom, vip.extintf) in zone_names else "interface"
                need(vdom, vip.extintf, kind, "vip", consumer, "target_zone")
                if kind == "zone":
                    zone = next(item for item in config.zones
                                if (item.vdom or "root", item.name) == (vdom, vip.extintf))
                    for member in zone.members or ():
                        need(vdom, member, "interface", "zone_membership",
                             ("zone_membership", vdom, vip.extintf), "target_interface")

    # If a consumed interface is an explicit member of a FortiGate zone, the
    # planner must preserve that zone rather than assume it already exists on
    # PAN-OS. Rendering the zone consumes target_interface for every explicit
    # member so a partial membership list can never be emitted silently.
    zone_memberships = {}
    for zone in getattr(config, "zones", ()):
        vdom = zone.vdom or "root"
        for member in zone.members or ():
            zone_memberships.setdefault((vdom, member), []).append(zone)

    zone_consuming_interfaces = [
        (vdom, name)
        for (vdom, name, kind), item in tuple(required.items())
        if kind == "interface" and "target_zone" in item["requires"]
    ]
    for vdom, name in zone_consuming_interfaces:
        for zone in zone_memberships.get((vdom, name), ()):
            consumer = ("zone_membership", vdom, zone.name)
            need(vdom, zone.name, "zone", "zone_membership", consumer, "target_zone")
            for member in zone.members or ():
                need(vdom, member, "interface", "zone_membership", consumer, "target_interface")

    # A child interface needs its explicit parent mapping only when the planned
    # target item itself consumes target_interface.
    source_interfaces = {(item.vdom or "root", item.name): item
                         for item in getattr(config, "interfaces", ()) if item.name}
    expanded_parents = set()
    while True:
        children = [
            (vdom, name)
            for (vdom, name, kind), item in required.items()
            if kind == "interface"
            and "target_interface" in item["requires"]
            and (vdom, name) not in expanded_parents
        ]
        if not children:
            break
        for vdom, name in children:
            expanded_parents.add((vdom, name))
            item = source_interfaces.get((vdom, name))
            if item and item.interface:
                need(vdom, item.interface, "interface", "interface_parent",
                     ("interface_parent", vdom, name), "target_interface")

    interfaces = []
    for _, value in sorted(required.items()):
        item = {key: val for key, val in value.items() if key != "_affected"}
        item["affected_by"] = {
            category: len(consumers) for category, consumers in sorted(value["_affected"].items())
        }
        item["affected_count"] = sum(item["affected_by"].values())
        item["reference_count"] = item["affected_count"]
        item["source_interface"] = value["source_name"]
        item["is_interface"] = value["kind"] == "interface"
        interfaces.append(item)

    zones = [{"source_vdom": vdom, "source_zone": name, "requires": ["target_zone"]}
             for (vdom, name, kind), item in sorted(required.items()) if kind == "zone"]
    required_keys = set(required)
    optional = [{"source_vdom": item.vdom or "root", "source_name": item.name, "kind": "interface"}
                for item in getattr(config, "interfaces", ())
                if item.name and (item.vdom or "root", item.name, "interface") not in required_keys]
    optional.extend({"source_vdom": item.vdom or "root", "source_name": item.name, "kind": "zone"}
                    for item in getattr(config, "zones", ())
                    if item.name and (item.vdom or "root", item.name, "zone") not in required_keys)

    return {
        "vdoms": [
            {"source_vdom": vdom, "requires": fields}
            for vdom, fields in sorted(required_vdom_fields.items())
            if fields
        ],
        "interfaces": interfaces,
        "zones": zones,
        "required_zones": [item["source_zone"] for item in zones],
        "required_zone_keys": [(item["source_vdom"], item["source_zone"]) for item in zones],
        "policy_interface_references": sorted({
            name
            for policy in getattr(config, "policies", ())
            for name in (*(policy.srcintf or ()), *(policy.dstintf or ()))
        }),
        "optional": optional,
        "topology_issues": [],
    }
