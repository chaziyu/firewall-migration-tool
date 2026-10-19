"""ASA/context-specific destination collision classification."""

from dataclasses import replace
from ipaddress import ip_interface

_FAMILY_EVIDENCE = {"interface": {"interfaces"}, "address": {"objects"}, "address_group": {"objects"},
                    "service": {"objects"}, "service_group": {"objects"}, "schedule": {"schedules"},
                    "static_route": {"routes"}, "policy": {"access_rules", "acl_bindings", "nat"},
                    "default_behavior": {"access_rules", "acl_bindings", "nat"},
                    "acl_binding": {"acl_bindings"}, "nat": {"nat", "access_rules", "acl_bindings"}}


def classify_target_reuse(plan, source, options, evidence):
    if evidence is None:
        return plan
    config = evidence["config"]
    complete = set(evidence["complete_families"])
    updated = []
    for item in plan.items:
        families = {"objects", "nat"} if item.family == "nat_pool" else _FAMILY_EVIDENCE.get(item.family)
        if families is None:
            updated.append(item)
            continue
        if not families <= complete:
            updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_FAMILY_COMPLETENESS_REQUIRED")))))
            continue
        if item.family in {"policy", "default_behavior", "nat"} and (
            config.nat_rules or any(row.nat_lines for row in config.network_objects)
        ):
            updated.append(replace(item, blockers=tuple(dict.fromkeys((
                *item.blockers, "TARGET_NAT_INTERACTIONS_UNVERIFIED",
            )))))
            continue
        if item.family == "interface":
            mapping = options.interfaces.get(item.source_vdom, {}).get(item.source_name)
            vlan_id = dict(item.settings).get("vlan_id")
            if vlan_id is not None and any(row.vlan_id == vlan_id for row in config.interfaces):
                updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_VLAN_TAG_CONFLICT")))))
                continue
            target = next((row for row in config.interfaces if row.name == getattr(mapping, "interface", None)), None)
            if target:
                source_if = next((row for row in source.interfaces if (row.vdom or "root") == item.source_vdom and row.name == item.source_name), None)
                try:
                    source_ip = str(source_if.ip).split() if source_if and source_if.ip else []
                    address_matches = not source_ip or (target.ip and target.mask and
                        ip_interface(f"{source_ip[0]}/{source_ip[1]}") == ip_interface(f"{target.ip}/{target.mask}"))
                except (ValueError, TypeError):
                    address_matches = False
                expected_shutdown = source_if.status == "down" if source_if and source_if.status in {"up", "down"} else None
                state_matches = (expected_shutdown is not None and "shutdown" in target.explicit_fields
                                 and target.shutdown is expected_shutdown)
                if (target.nameif == mapping.nameif and target.security_level == mapping.security_level
                        and address_matches and state_matches and not target.raw_extra
                        and not target.requires_manual_review and target.interface_type == "physical"
                        and not any((target.standby_ip, target.management_only, target.ipv6_addresses,
                                     target.ipv6_autoconfig, target.ipv6_dhcp, target.policy_route_maps,
                                     target.traffic_zone_members, target.channel_group, target.mtu))):
                    updated.append(replace(item, settings=(("commands", ()),), target_disposition="REUSE"))
                else:
                    updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_INTERFACE_CONFLICT")))))
                continue
        elif item.family in {"address", "nat_pool", "address_group", "service", "service_group", "schedule"}:
            collections = {"address": config.network_objects, "address_group": config.network_groups,
                           "nat_pool": config.network_objects,
                           "service": config.service_objects, "service_group": config.service_groups,
                           "schedule": config.time_ranges}
            target = next((row for row in collections[item.family] if row.name == item.target_name), None)
            if target:
                expected = tuple(" ".join(line.split()) for line in dict(item.settings).get("commands", ())[1:])
                actual = tuple(" ".join(line.split()) for line in target.raw_lines)
                if (item.family in {"address", "nat_pool"} and expected and expected == actual
                        and len([row for row in config.network_objects if row.name == item.target_name]) == 1
                        and not target.raw_extra and not target.nat_lines and not target.requires_manual_review):
                    updated.append(replace(item, settings=(("commands", ()),), target_disposition="REUSE"))
                    continue
                updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_OBJECT_CONFLICT")))))
                continue
        elif item.family == "static_route":
            command = next(iter(dict(item.settings).get("commands", ())), "").split()
            target_nameif = command[1] if len(command) > 1 else ""
            destination = command[2] if len(command) > 2 else ""
            mask = command[3] if len(command) > 3 else ""
            target = next((row for row in config.static_routes if row.interface == target_nameif and row.destination == destination and row.mask == mask), None)
            if target:
                if target.gateway == (command[4] if len(command) > 4 else None) and target.administrative_distance == (int(command[5]) if len(command) > 5 and command[5].isdigit() else 1):
                    updated.append(replace(item, settings=(("commands", ()),), target_disposition="REUSE"))
                else:
                    updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_ROUTE_CONFLICT")))))
                continue
        elif item.family in {"policy", "default_behavior"}:
            acl_names = {command.split()[1] for command in dict(item.settings).get("commands", ()) if command.startswith("access-list ")}
            if any(row.acl_name in acl_names for row in config.access_rules):
                updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_ACL_NAME_CONFLICT")))))
                continue
        elif item.family == "acl_binding":
            mapping = options.interfaces.get(item.source_vdom, {}).get(item.source_name)
            bindings = evidence["existing_bindings"].get(mapping.nameif if mapping else "", ())
            if bindings:
                updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "EXISTING_ACCESS_GROUP_BINDING_CONFLICT")))))
                continue
        updated.append(item)
    return replace(plan, items=tuple(updated))
