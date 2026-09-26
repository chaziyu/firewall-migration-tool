"""Compare planned PAN-OS items with explicit target objects."""

from .models import PANMigrationPlan
from .target_candidates import PANTargetCandidateMatchClass, build_target_candidates
from .target_suggestions import _device


def _fields(item):
    return getattr(item, "explicit_fields", set()) or set()


def _address(source, target):
    field = {"ip-netmask": "ip_netmask", "ip-range": "ip_range",
             "ip-wildcard": "ip_wildcard", "fqdn": "fqdn"}.get(source.address_type)
    if field is None:
        return (), ("source address form is unsupported for exact comparison",), ()
    contradictions = [f"target {name} is also configured"
                      for name in {"ip_netmask", "ip_range", "ip_wildcard", "fqdn"} - {field}
                      if name in _fields(target) and getattr(target, name, None) is not None]
    if field not in _fields(target):
        return (), (f"target {field} is not explicit",), tuple(contradictions)
    if getattr(target, field, None) != source.value:
        contradictions.append(f"target {field} differs")
    return ((f"same explicit {field}",), (), tuple(contradictions)) if not contradictions else ((), (), tuple(contradictions))


def _members(source, target):
    field = "members" if source.source_object_type == "service_group" else "static_members"
    if field not in _fields(target):
        return (), (f"target {field} is not explicit",), ()
    if set(getattr(target, field) or ()) == set(source.members):
        return ("same explicit members",), (), ()
    return (), (), ("target members differ",)


def _service(source, target):
    expected_protocol = source.protocol
    if expected_protocol not in _fields(target):
        return (), (f"target {expected_protocol} protocol is not explicit",), ()
    strong, supporting, contradictions = [], [], []
    for other in {"tcp", "udp"} - {expected_protocol}:
        if getattr(target, other, None) is not None:
            contradictions.append(f"target has explicit {other} service semantics")
    protocol = getattr(target, expected_protocol, None)
    if protocol is None:
        return (), (f"target {expected_protocol} service is absent",), tuple(contradictions)
    for field, value in (("port", source.destination_port), ("source_port", source.source_port)):
        if field not in _fields(protocol):
            supporting.append(f"target {expected_protocol} {field} is not explicit")
        elif getattr(protocol, field, None) == value:
            strong.append(f"same explicit {expected_protocol} {field}")
        else:
            contradictions.append(f"target {expected_protocol} {field} differs")
    return tuple(strong), tuple(supporting), tuple(contradictions)


def _schedule(source, target):
    if source.schedule_type == "one-time":
        if "non_recurring" not in _fields(target):
            return (), ("target non_recurring is not explicit",), ()
        if list(target.non_recurring or ()) == [f"{start}-{end}" for start, end in source.non_recurring]:
            return ("same explicit non-recurring schedule",), (), ()
        return (), (), ("target non-recurring schedule differs",)
    if source.schedule_type != "recurring" or target.recurring is None:
        return (), ("target recurring schedule is absent",), ()
    recurring = target.recurring
    explicit = _fields(recurring)
    if source.weekly:
        expected = {}
        for day, start, end in source.weekly:
            expected.setdefault(day, []).append(f"{start}-{end}")
        if "weekly" not in explicit:
            return (), ("target weekly schedule is not explicit",), ()
        if recurring.weekly == expected and "daily" not in explicit:
            return ("same explicit weekly schedule",), (), ()
        return (), (), ("target weekly schedule differs",)
    expected_daily = [f"{start}-{end}" for start, end in source.daily]
    if "daily" not in explicit:
        return (), ("target daily schedule is not explicit",), ()
    if recurring.daily == expected_daily and "weekly" not in explicit:
        return ("same explicit daily schedule",), (), ()
    return (), (), ("target daily schedule differs",)


def _classify(target, family, attribute, item, device, compare):
    name = item.target_name
    if not name:
        return None
    candidates = build_target_candidates(target, attribute, family, name, device, item.target_vsys,
                                         comparator=compare, source_object=item)
    if not candidates:
        return {"status": "NO_MATCH", "family": family, "source_name": item.source_name,
                "source_vdom": item.source_vdom or "root", "target_name": name}
    candidate = candidates[0]
    if len(candidates) > 1 or candidate.match_class == PANTargetCandidateMatchClass.AMBIGUOUS:
        status = "AMBIGUOUS"
    elif candidate.contradictions:
        status = "NAME_CONFLICT"
    elif candidate.strong_evidence and not candidate.supporting_evidence:
        status = "EXACT_MATCH"
    else:
        status = "AMBIGUOUS"
    return {"status": status, "family": family, "source_name": item.source_name,
            "source_vdom": item.source_vdom or "root", "target_name": candidate.name,
            "target_scope": candidate.scope_identity,
            "evidence": list(candidate.strong_evidence + candidate.supporting_evidence + candidate.contradictions)}


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
                "target_name": existing[0].name})
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
            "target_name": matches[0].name})
    return result


def classify_target_object_reuse(plan: PANMigrationPlan, target, device: str | None):
    """Classify items from the actual plan; never rerun planner functions here."""
    if target is None or not device:
        return ()
    result = []
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
