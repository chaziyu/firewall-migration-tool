"""Compare planned PAN-OS items with explicit target objects."""

from .models import PANMigrationPlan
from .target_candidates import PANTargetCandidateMatchClass, build_target_candidates
from .target_suggestions import _device
from ...vendors.palo_alto.source_model import pan_scope_identity


def _fields(item):
    return getattr(item, "explicit_fields", set()) or set()


def _address(source, target):
    field = {"ip-netmask": "ip_netmask", "ip-range": "ip_range",
             "ip-wildcard": "ip_wildcard", "fqdn": "fqdn"}.get(source.address_type)
    if field is None:
        return (), ("source address form is unsupported for exact comparison",), ()
    forms = {"ip_netmask", "ip_range", "ip_wildcard", "fqdn"}
    configured = {name for name in forms if name in _fields(target) and getattr(target, name, None) is not None}
    supporting = ["target has unknown address semantics"] if target.raw_extra else []
    contradictions = [f"target {name} is also configured" for name in configured - {field}]
    if field not in configured:
        supporting.append(f"target {field} is not explicitly configured")
    if len(configured) != 1:
        supporting.append("target address does not have exactly one explicit address form")
    if field in configured and getattr(target, field, None) != source.value:
        contradictions.append(f"target {field} differs")
    strong = (f"same explicit {field}",) if field in configured and not contradictions else ()
    return strong, tuple(supporting), tuple(contradictions)


def _members(source, target):
    field = "members" if source.source_object_type == "service_group" else "static_members"
    supporting = []
    if target.raw_extra:
        supporting.append("target has unknown group semantics")
    if source.source_object_type == "address_group" and (
        "dynamic_filter" in _fields(target) or target.dynamic_filter is not None
    ):
        supporting.append("target has dynamic address-group semantics")
    if field not in _fields(target) or getattr(target, field, None) is None:
        supporting.append(f"target {field} is not explicit")
        return (), tuple(supporting), ()
    if set(getattr(target, field) or ()) != set(source.members):
        return (), tuple(supporting), ("target members differ",)
    return (("same explicit members",), tuple(supporting), ())


def _service(source, target):
    expected_protocol = source.protocol
    if expected_protocol not in _fields(target):
        return (), (f"target {expected_protocol} protocol is not explicit",), ()
    strong, supporting, contradictions = [], [], []
    if target.raw_extra:
        supporting.append("target has unknown service semantics")
    for other in {"tcp", "udp"} - {expected_protocol}:
        if getattr(target, other, None) is not None:
            contradictions.append(f"target has explicit {other} service semantics")
    protocol = getattr(target, expected_protocol, None)
    if protocol is None:
        return (), (f"target {expected_protocol} service is absent",), tuple(contradictions)
    if protocol.raw_extra:
        supporting.append(f"target {expected_protocol} has unknown protocol semantics")
    if protocol.override is not None:
        supporting.append(f"target contains explicit {expected_protocol} override semantics")
    for field, value in (("port", source.destination_port), ("source_port", source.source_port)):
        if field not in _fields(protocol):
            supporting.append(f"target {expected_protocol} {field} is not explicit")
        elif getattr(protocol, field, None) == value:
            strong.append(f"same explicit {expected_protocol} {field}")
        else:
            contradictions.append(f"target {expected_protocol} {field} differs")
    return tuple(strong), tuple(supporting), tuple(contradictions)


def _schedule(source, target):
    supporting = []
    root_fields = _fields(target)
    if target.raw_extra:
        supporting.append("target has unknown schedule semantics")
    if source.schedule_type == "one-time":
        if "non_recurring" not in root_fields or target.non_recurring is None:
            supporting.append("target non-recurring schedule is not explicit")
        if "recurring" in root_fields or target.recurring is not None:
            supporting.append("target also has recurring schedule semantics")
        if target.non_recurring is not None and list(target.non_recurring) != [f"{start}-{end}" for start, end in source.non_recurring]:
            return (), tuple(supporting), ("target non-recurring schedule differs",)
        if "non_recurring" not in root_fields or target.non_recurring is None:
            return (), tuple(supporting), ()
        return ("same explicit non-recurring schedule",), tuple(supporting), ()
    if source.schedule_type != "recurring" or target.recurring is None:
        return (), ("target recurring schedule is absent",), ()
    recurring = target.recurring
    explicit = _fields(recurring)
    if recurring.raw_extra:
        supporting.append("target recurring schedule has unknown semantics")
    if source.weekly:
        expected = {}
        for day, start, end in source.weekly:
            expected.setdefault(day, []).append(f"{start}-{end}")
        if "weekly" not in explicit or recurring.weekly is None:
            supporting.append("target weekly schedule is not explicit")
        if "daily" in explicit or "non_recurring" in root_fields or target.non_recurring is not None:
            supporting.append("target also has daily or one-time schedule semantics")
        if recurring.weekly is not None and recurring.weekly != expected:
            return (), tuple(supporting), ("target weekly schedule differs",)
        if "weekly" not in explicit or recurring.weekly is None:
            return (), tuple(supporting), ()
        return ("same explicit weekly schedule",), tuple(supporting), ()
    expected_daily = [f"{start}-{end}" for start, end in source.daily]
    if "daily" not in explicit or recurring.daily is None:
        supporting.append("target daily schedule is not explicit")
    if "weekly" in explicit or "non_recurring" in root_fields or target.non_recurring is not None:
        supporting.append("target also has weekly or one-time schedule semantics")
    if recurring.daily is not None and recurring.daily != expected_daily:
        return (), tuple(supporting), ("target daily schedule differs",)
    if "daily" not in explicit or recurring.daily is None:
        return (), tuple(supporting), ()
    return ("same explicit daily schedule",), tuple(supporting), ()


def _dhcp_pool_values(target):
    values = []
    supporting = []
    for pool in getattr(target, "ip_pools", None) or ():
        explicit = _fields(pool)
        if getattr(pool, "raw_extra", None):
            supporting.append("target DHCP pool has unknown semantics")
        if "value" in explicit and getattr(pool, "value", None):
            values.append(str(pool.value))
        elif {"start_ip", "end_ip"} <= explicit and pool.start_ip and pool.end_ip:
            values.append(f"{pool.start_ip}-{pool.end_ip}")
        else:
            supporting.append("target DHCP pool is not explicitly comparable")
    return tuple(values), tuple(supporting)


def _dhcp(source, target):
    explicit = _fields(target)
    strong = []
    supporting = []
    contradictions = []
    if getattr(target, "raw_extra", None):
        supporting.append("target DHCP server has unknown semantics")

    target_interface = getattr(target, "interface", None) or getattr(target, "name", None)
    if target_interface != source.interface:
        contradictions.append("target DHCP interface differs")
    else:
        strong.append("same interface-scoped DHCP server")

    for field in ("mode", "gateway", "subnet_mask", "dns_primary", "dns_secondary"):
        expected = getattr(source, field, None)
        actual = getattr(target, field, None)
        if expected is None:
            if field in explicit and actual not in (None, "", [], ()):
                contradictions.append(f"target DHCP {field} is explicitly configured but absent from the plan")
        elif field not in explicit:
            supporting.append(f"target DHCP {field} is not explicit")
        elif str(actual) == str(expected):
            strong.append(f"same explicit DHCP {field}")
        else:
            contradictions.append(f"target DHCP {field} differs")

    if source.lease_type is None:
        if "lease_type" in explicit and getattr(target, "lease_type", None):
            contradictions.append("target DHCP lease is explicitly configured but absent from the plan")
    elif "lease_type" not in explicit:
        supporting.append("target DHCP lease type is not explicit")
    elif target.lease_type != source.lease_type:
        contradictions.append("target DHCP lease type differs")
    else:
        strong.append("same explicit DHCP lease type")
        if source.lease_type == "timeout":
            if "lease_timeout" not in explicit:
                supporting.append("target DHCP lease timeout is not explicit")
            elif str(target.lease_timeout) == str(source.lease_timeout):
                strong.append("same explicit DHCP lease timeout")
            else:
                contradictions.append("target DHCP lease timeout differs")

    if "ip_pools" not in explicit or getattr(target, "ip_pools", None) is None:
        supporting.append("target DHCP IP pools are not explicit")
    else:
        pools, pool_supporting = _dhcp_pool_values(target)
        supporting.extend(pool_supporting)
        if not pool_supporting and set(pools) == set(source.ip_pools):
            strong.append("same explicit DHCP IP pools")
        elif not pool_supporting:
            contradictions.append("target DHCP IP pools differ")

    represented = {
        "interface", "mode", "lease_type", "lease_timeout", "gateway",
        "subnet_mask", "dns_primary", "dns_secondary", "ip_pools",
    }
    additional = sorted(field for field in explicit - represented
                        if getattr(target, field, None) not in (None, "", [], ()))
    if additional:
        supporting.append("target DHCP has additional explicit semantics: " + ", ".join(additional))
    return tuple(strong), tuple(supporting), tuple(contradictions)


def _dhcp_collisions(planned, target, device):
    result = []
    records = [
        item for item in getattr(target.config, "dhcp_servers", ())
        if (
            _device(item) == device
            or getattr(getattr(item, "scope", None), "kind", None) == "shared"
        )
    ]
    for source in planned:
        if source.status.value != "SUPPORTED":
            continue
        matches = [
            item for item in records
            if (getattr(item, "interface", None) or getattr(item, "name", None)) == source.interface
        ]
        if not matches:
            continue
        if len(matches) > 1:
            result.append({
                "status": "AMBIGUOUS", "family": "dhcp_server",
                "source_name": source.source_name, "source_vdom": source.source_vdom or "root",
                "source_kind": source.source_kind, "target_vsys": source.target_vsys,
                "target_name": source.target_name,
                "evidence": ["multiple target DHCP servers match the mapped interface"],
            })
            continue
        target_item = matches[0]
        strong, supporting, contradictions = _dhcp(source, target_item)
        if contradictions:
            status = "NAME_CONFLICT"
        elif strong and not supporting:
            status = "EXACT_MATCH"
        else:
            status = "AMBIGUOUS"
        result.append({
            "status": status, "family": "dhcp_server",
            "source_name": source.source_name, "source_vdom": source.source_vdom or "root",
            "source_kind": source.source_kind, "target_vsys": source.target_vsys,
            "target_name": source.target_name,
            "evidence": list((*strong, *supporting, *contradictions)),
        })
    return result


def _classify(target, family, attribute, item, device, compare):
    name = item.target_name
    if not name:
        return None
    candidates = build_target_candidates(target, attribute, family, name, device, item.target_vsys,
                                         comparator=compare, source_object=item)
    if not candidates:
        return {"status": "NO_MATCH", "family": family, "source_name": item.source_name,
                "source_vdom": item.source_vdom or "root", "source_kind": item.source_kind,
                "target_vsys": item.target_vsys, "target_name": name}
    candidate = candidates[0]
    if len(candidates) > 1 or candidate.match_class == PANTargetCandidateMatchClass.AMBIGUOUS:
        status = "AMBIGUOUS"
    elif candidate.contradictions:
        status = "NAME_CONFLICT"
    elif candidate.strong_evidence and not candidate.supporting_evidence and not candidate.contradictions:
        status = "EXACT_MATCH"
    else:
        status = "AMBIGUOUS"
    return {"status": status, "family": family, "source_name": item.source_name,
            "source_vdom": item.source_vdom or "root", "source_kind": item.source_kind,
            "target_vsys": item.target_vsys, "target_name": candidate.name,
            "target_scope": candidate.scope_identity,
            "evidence": list(candidate.strong_evidence + candidate.supporting_evidence + candidate.contradictions)}


def _interface_collisions(planned, target, device):
    """Compare planned interfaces with explicit device/topology evidence."""
    if not planned:
        return []
    records = [
        item for item in (*getattr(target.config, "interfaces", ()),
                          *getattr(target.config, "interface_units", ()))
        if item.name and _device(item) == device
    ]
    topology = {
        (item.scope, item.interface): item
        for item in getattr(getattr(target, "derived", None), "interface_topology", ())
    }
    result = []
    for source in planned:
        matches = [item for item in records if item.name == source.target_name]
        if not matches:
            continue
        evidence = []
        contradictions = []
        supporting = []
        if len(matches) != 1:
            result.append({
                "status": "AMBIGUOUS", "family": "interface",
                "source_name": source.source_name, "source_vdom": source.source_vdom or "root",
                "source_kind": source.source_kind, "target_vsys": source.target_vsys,
                "target_name": source.target_name,
                "evidence": ["multiple target interfaces share the mapped name"],
            })
            continue

        target_item = matches[0]
        explicit = _fields(target_item)
        if getattr(target_item, "interface_family", None) != source.interface_family:
            contradictions.append("target interface family differs")
        else:
            evidence.append("same explicit target interface family")

        target_parent = getattr(target_item, "parent", None)
        if source.parent != target_parent:
            contradictions.append("target interface parent differs")
        elif source.parent:
            evidence.append("same explicit parent interface")

        if source.parent:
            if "tag" not in explicit:
                supporting.append("target VLAN tag is not explicit")
            elif str(getattr(target_item, "tag", None)) != str(source.tag):
                contradictions.append("target VLAN tag differs")
            else:
                evidence.append("same explicit VLAN tag")
        else:
            mode = getattr(target_item, "mode", None)
            if "mode" not in explicit:
                supporting.append("target interface mode is not explicit")
            elif mode != "layer3":
                contradictions.append("target interface is not explicitly layer3")
            else:
                evidence.append("same explicit layer3 mode")

        planned_addresses = tuple(source.ipv4_addresses)
        target_addresses = tuple(getattr(target_item, "ipv4_addresses", None) or ())
        if planned_addresses:
            if "ipv4_addresses" not in explicit:
                supporting.append("target IPv4 addresses are not explicit")
            elif set(target_addresses) != set(planned_addresses):
                contradictions.append("target IPv4 addresses differ")
            else:
                evidence.append("same explicit IPv4 addresses")
        elif "ipv4_addresses" in explicit and target_addresses:
            contradictions.append("target has explicit IPv4 addresses absent from the planned source state")

        allowed_fields = {"tag", "ipv4_addresses"} if source.parent else {"mode", "ipv4_addresses"}
        extras = sorted(explicit - allowed_fields)
        if extras:
            supporting.append("target has additional explicit interface semantics: " + ", ".join(extras))
        if getattr(target_item, "raw_extra", None):
            supporting.append("target interface has preserved unknown semantics")

        topo = topology.get((pan_scope_identity(getattr(target_item, "scope", None)), target_item.name))
        if topo is None:
            supporting.append("target interface topology evidence is unavailable")
        else:
            if topo.issues:
                supporting.extend(topo.issues)
            if source.target_vsys not in topo.imported_vsys:
                contradictions.append("target VSYS import differs")
            else:
                evidence.append("same explicit VSYS import")
            if source.virtual_router not in topo.virtual_routers:
                contradictions.append("target virtual-router membership differs")
            else:
                evidence.append("same explicit virtual-router membership")

        status = (
            "NAME_CONFLICT" if contradictions else
            "AMBIGUOUS" if supporting else
            "EXACT_MATCH"
        )
        result.append({
            "status": status, "family": "interface",
            "source_name": source.source_name, "source_vdom": source.source_vdom or "root",
            "source_kind": source.source_kind, "target_vsys": source.target_vsys,
            "target_name": source.target_name,
            "evidence": [*evidence, *supporting, *contradictions],
        })
    return result


def _route_collisions(planned, target, device):
    result = []
    routers = [router for router in getattr(target.config, "virtual_routers", ())
               if router.name and _device(router) == device]
    for route in planned:
        in_router = [entry for router in routers if router.name == route.virtual_router
                     for entry in (router.static_routes or ())]
        existing = [entry for entry in in_router
                    if entry.name == route.target_name or entry.destination == route.destination]
        if existing:
            fields = (
                    ("destination", "destination", route.destination),
                    ("nexthop_type", "nexthop_type", route.nexthop_type),
                    ("nexthop_ip_address", "nexthop_ip_address", route.nexthop),
                    ("admin_distance", "admin_distance", str(route.admin_distance) if route.admin_distance is not None else None),
                    ("interface", "interface", route.interface))
            explicit = _fields(existing[0]) if len(existing) == 1 else set()
            same = len(existing) == 1 and all(field in explicit and getattr(existing[0], target_field, None) == expected
                                               for field, target_field, expected in fields if expected is not None)
            differs = len(existing) == 1 and any(field in explicit and getattr(existing[0], target_field, None) != expected
                                                  for field, target_field, expected in fields)
            status = "AMBIGUOUS" if len(existing) > 1 or same or not differs else "NAME_CONFLICT"
            result.append({"status": status,
                "family": "static_route", "source_name": route.source_name, "source_vdom": route.source_vdom or "root",
                "source_kind": route.source_kind, "target_vsys": route.target_vsys, "target_name": existing[0].name})
    return result


def _rule_collisions(planned, target, device, family, attribute, fields):
    result = []
    records = [item for item in getattr(target.config, attribute, ()) if item.name and _device(item) == device]
    for rule in planned:
        matches = [item for item in records if item.name == rule.target_name
                   and (not rule.target_vsys or not item.scope or item.scope.vsys == rule.target_vsys)]
        if not matches:
            continue
        exact = False
        if len(matches) == 1:
            existing = matches[0]
            explicit = _fields(existing)
            values = fields(rule)
            differs = any(field in explicit and
                          ((tuple(getattr(existing, target_field) or ()) != tuple(expected)) if isinstance(expected, tuple)
                           else getattr(existing, target_field, None) != expected)
                          for field, target_field, expected in values)
        else:
            differs = False
        result.append({"status": "AMBIGUOUS" if len(matches) > 1 or not differs else "NAME_CONFLICT",
            "family": family, "source_name": rule.source_name, "source_vdom": rule.source_vdom or "root",
            "source_kind": rule.source_kind, "target_vsys": rule.target_vsys, "target_name": matches[0].name})
    return result


def classify_target_object_reuse(plan: PANMigrationPlan, target, device: str | None):
    """Classify items from the actual plan; never rerun planner functions here."""
    if target is None or not device:
        return ()
    result = []
    result.extend(_interface_collisions(plan.interfaces, target, device))
    for family, attribute, items, compare in (
        ("address", "addresses", plan.addresses, _address),
        ("address_group", "address_groups", plan.address_groups, _members),
        ("service", "services", plan.services, _service),
        ("service_group", "service_groups", plan.service_groups, _members),
        ("schedule", "schedules", plan.schedules, _schedule),
    ):
        result.extend(found for item in items if item.status.value == "SUPPORTED"
                      if (found := _classify(target, family, attribute, item, device, compare)) is not None)
    result.extend(_route_collisions(plan.static_routes, target, device))
    result.extend(_dhcp_collisions(plan.dhcp_servers, target, device))
    result.extend(_rule_collisions(plan.nat_rules, target, device, "nat_rule", "nat_rules", lambda rule: (
        ("from_zones", "from_zones", rule.from_zones), ("to_zones", "to_zones", rule.to_zones),
        ("source", "source", rule.source_addresses), ("destination", "destination", rule.destination_addresses),
        ("service", "service", rule.service), ("to_interface", "to_interface", rule.to_interface))))
    nat_records = [item for item in getattr(target.config, "nat_rules", ()) if item.name and _device(item) == device]
    for rule in plan.nat_rules:
        if not rule.target_name:
            continue
        overlaps = [item for item in nat_records if item.name != rule.target_name
                    and (not rule.target_vsys or not item.scope or item.scope.vsys == rule.target_vsys)
                    and rule.from_zones and item.from_zones and set(rule.from_zones) & set(item.from_zones)
                    and rule.to_zones and item.to_zones and set(rule.to_zones) & set(item.to_zones)
                    and rule.source_addresses and item.source and set(rule.source_addresses) & set(item.source)
                    and rule.destination_addresses and item.destination and set(rule.destination_addresses) & set(item.destination)
                    and rule.service and item.service == rule.service]
        if overlaps:
            result.append({"status": "AMBIGUOUS", "family": "nat_rule", "source_name": rule.source_name,
                           "source_vdom": rule.source_vdom or "root", "target_name": overlaps[0].name})
    result.extend(_rule_collisions(plan.security_rules, target, device, "security_rule", "security_rules", lambda rule: (
        ("from_zones", "from_zones", rule.from_zones), ("to_zones", "to_zones", rule.to_zones),
        ("source", "source", rule.sources), ("destination", "destination", rule.destinations),
        ("service", "service", rule.services), ("schedule", "schedule", rule.schedule), ("action", "action", rule.action))))
    return tuple(sorted(result, key=lambda item: (item["family"], item["source_vdom"], item["source_name"])))
