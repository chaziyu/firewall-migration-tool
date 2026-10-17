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
        families = _FAMILY_EVIDENCE.get(item.family)
        if families is None:
            updated.append(item)
            continue
        if not families <= complete:
            updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_FAMILY_COMPLETENESS_REQUIRED")))))
            continue
        if item.family == "interface":
            mapping = options.interfaces.get(item.source_vdom, {}).get(item.source_name)
            target = next((row for row in config.interfaces if row.name == getattr(mapping, "interface", None)), None)
            if target:
                source_if = next((row for row in source.interfaces if (row.vdom or "root") == item.source_vdom and row.name == item.source_name), None)
                try:
                    source_ip = str(source_if.ip).split() if source_if and source_if.ip else []
                    address_matches = not source_ip or (target.ip and target.mask and
                        ip_interface(f"{source_ip[0]}/{source_ip[1]}").ip == ip_interface(f"{target.ip}/{target.mask}").ip)
                except (ValueError, TypeError):
                    address_matches = False
                expected_shutdown = source_if.status == "down" if source_if and source_if.status in {"up", "down"} else None
                state_matches = (expected_shutdown is not None and "shutdown" in target.explicit_fields
                                 and target.shutdown is expected_shutdown)
                if (target.nameif == mapping.nameif and target.security_level == mapping.security_level
                        and address_matches and state_matches):
                    updated.append(replace(item, settings=(("commands", ()),), target_disposition="REUSE"))
                else:
                    updated.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_INTERFACE_CONFLICT")))))
                continue
        elif item.family in {"address", "address_group", "service", "service_group", "schedule"}:
            collections = {"address": config.network_objects, "address_group": config.network_groups,
                           "service": config.service_objects, "service_group": config.service_groups,
                           "schedule": config.time_ranges}
            target = next((row for row in collections[item.family] if row.name == item.target_name), None)
            if target:
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
