"""Compact, provenance-labeled evidence for FortiGate to PAN-OS review."""


def build_review_evidence(config, derived):
    interfaces = {(item.vdom or "root", item.name): item for item in config.interfaces if item.name}
    evidence = {}
    for key, interface in interfaces.items():
        explicit = getattr(interface, "explicit_fields", None)
        source = {}
        for field in ("type", "role", "vlanid", "interface", "vrf", "ip", "members"):
            value = getattr(interface, field, None)
            if value is not None and (explicit is None or field in explicit):
                source[field] = list(value) if isinstance(value, (list, tuple)) else value

        topology = next((item for item in derived.topology.interfaces
                         if (item.vdom or "root", item.name) == key), None)
        policy_src = sum(interface.name in (policy.srcintf or ()) and (policy.vdom or "root") == key[0]
                         for policy in config.policies)
        policy_dst = sum(interface.name in (policy.dstintf or ()) and (policy.vdom or "root") == key[0]
                         for policy in config.policies)
        route_count = sum(route.device == interface.name and (route.vdom or "root") == key[0]
                          for route in config.static_routes)
        nat_count = sum(interface.name in (item.egress_interfaces or ()) and item.vdom == key[0]
                        for item in derived.nat)
        sdwan_count = sum(member.interface == interface.name and (sdwan.vdom or "root") == key[0]
                          for sdwan in config.sdwans for member in sdwan.members)
        vpn = [item for item in derived.topology.vpns if (item.vdom or "root") == key[0]
               and item.attached_interface == interface.name]
        derived_facts = {}
        if topology is not None:
            derived_facts.update({"topology_kind": topology.kind, "topology_parent": topology.parent,
                "aggregate": topology.aggregate, "physical_interfaces": list(topology.physical_interfaces)})
        memberships = [zone.name for zone in config.zones if (zone.vdom or "root") == key[0]
                      and interface.name in (zone.members or ())]
        if memberships:
            source["zone_membership"] = memberships
        if policy_src or policy_dst:
            derived_facts.update({"policy_source_reference_count": policy_src,
                                  "policy_destination_reference_count": policy_dst})
        if route_count:
            derived_facts["static_route_usage"] = route_count
        if nat_count:
            derived_facts["nat_egress_usage"] = nat_count
        if vpn:
            derived_facts.update({"vpn_attachment_count": len(vpn), "vpn_names": [item.name for item in vpn],
                                  "vpn_physical_interfaces": list(dict.fromkeys(
                                      name for item in vpn for name in item.physical_interfaces))})
        if sdwan_count:
            derived_facts["sdwan_membership_count"] = sdwan_count
        evidence[key] = {"source_explicit": source, "derived_relationships": derived_facts}
    return evidence
