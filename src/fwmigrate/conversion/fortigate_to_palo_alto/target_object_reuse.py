"""Exact semantic reuse checks for same-name PAN-OS objects."""

from dataclasses import replace
import json

from .addresses import plan_addresses
from .models import PANMigrationStatus
from .nat import plan_nat
from .policies import plan_policies
from .recommendations import scoped_target_candidates
from .schedules import plan_schedules
from .services import plan_services
from .target_candidates import PANTargetCandidateMatchClass
from .target_suggestions import _device


def _address(source, target):
    kind = source.address_type
    field = {"ip-netmask": "ip_netmask", "ip-range": "ip_range",
             "ip-wildcard": "ip_wildcard", "fqdn": "fqdn"}.get(kind)
    if field is None:
        return (), ("source address form is unsupported for exact comparison",), ()
    explicit = getattr(target, "explicit_fields", set()) or set()
    others = {"ip_netmask", "ip_range", "ip_wildcard", "fqdn"} - {field}
    contradictions = [f"target {name} is also configured" for name in others
                      if name in explicit and getattr(target, name, None) is not None]
    if field not in explicit:
        return (), (f"target {field} is not explicit",), tuple(contradictions)
    if getattr(target, field, None) != source.value:
        contradictions.append(f"target {field} differs")
    return ((f"same explicit {field}",), (), tuple(contradictions)) if not contradictions else ((), (), tuple(contradictions))


def _members(source, target):
    explicit = getattr(target, "explicit_fields", set()) or set()
    field = "members" if source.source_object_type == "service_group" else "static_members"
    if field not in explicit:
        return (), (f"target {field} is not explicit",), ()
    if set(source.members) == set(getattr(target, field, None) or ()):
        return ("same explicit members",), (), ()
    return (), (), ("target members differ",)


def _service(source, target):
    expected = source.protocol
    strong, supporting, contradictions = [], [], []
    for protocol in ("tcp", "udp"):
        actual = getattr(target, protocol, None)
        if protocol != expected:
            if actual is not None:
                contradictions.append(f"target has explicit {protocol} service semantics")
            continue
        if actual is None:
            supporting.append(f"target {protocol} protocol is absent")
            continue
        for target_field, source_value in (("port", source.destination_port), ("source_port", source.source_port)):
            if target_field not in (getattr(actual, "explicit_fields", set()) or set()):
                supporting.append(f"target {protocol} {target_field} is not explicit")
            elif getattr(actual, target_field, None) == source_value:
                strong.append(f"same explicit {protocol} {target_field}")
            else:
                contradictions.append(f"target {protocol} {target_field} differs")
    return tuple(strong), tuple(supporting), tuple(contradictions)


def _schedule(source, target):
    if source.schedule_type == "one-time":
        if "non_recurring" not in (getattr(target, "explicit_fields", set()) or set()):
            return (), ("target non_recurring is not explicit",), ()
        same = list(target.non_recurring or ()) == [f"{start}-{end}" for start, end in source.non_recurring]
    elif source.schedule_type == "recurring":
        recurring = target.recurring
        if recurring is None:
            return (), ("target recurring schedule is absent",), ()
        if source.weekly:
            expected = {}
            for day, start, end in source.weekly:
                expected.setdefault(day, []).append(f"{start}-{end}")
            if "weekly" not in (getattr(recurring, "explicit_fields", set()) or set()):
                return (), ("target weekly schedule is not explicit",), ()
            same = recurring.weekly == expected
        else:
            expected = [f"{start}-{end}" for _, start, end in source.weekly]
            if "daily" not in (getattr(recurring, "explicit_fields", set()) or set()):
                return (), ("target daily schedule is not explicit",), ()
            same = recurring.daily == expected
    else:
        return (), ("source schedule form is not supported for exact comparison",), ()
    return (("same explicit schedule",), (), ()) if same else ((), (), ("target schedule differs",))


def _classify(target, family, attribute, source, comparator, device, decisions):
    candidates = scoped_target_candidates(target, attribute, family, source.source_name,
        source.source_vdom or "root", decisions, device, comparator=comparator, source_object=source)
    if not candidates:
        return {"status": "NO_MATCH", "family": family, "source_name": source.source_name,
                "source_vdom": source.source_vdom or "root"}
    candidate = candidates[0]
    if (candidate.match_class == PANTargetCandidateMatchClass.EXACT_EQUIVALENT
            or candidate.match_class == PANTargetCandidateMatchClass.LIKELY_REUSE
            and candidate.strong_evidence and not candidate.supporting_evidence):
        status = "EXACT_MATCH"
    elif candidate.match_class in {PANTargetCandidateMatchClass.AMBIGUOUS, PANTargetCandidateMatchClass.POSSIBLE,
                                   PANTargetCandidateMatchClass.LIKELY_REUSE}:
        status = "AMBIGUOUS"
    else:
        status = "NAME_CONFLICT"
    return {"status": status, "family": family, "source_name": source.source_name,
            "source_vdom": source.source_vdom or "root", "target_name": candidate.name,
            "target_scope": candidate.scope_identity,
            "evidence": list(candidate.strong_evidence + candidate.supporting_evidence + candidate.contradictions)}


def classify_target_object_reuse(config, derived, decisions, target, device):
    """Classify same-name address, service, and schedule objects by explicit semantics."""
    if target is None or not device:
        return ()
    options = decisions.to_options()
    addresses, groups, _ = plan_addresses(config, options)
    services, service_groups = plan_services(derived, options)
    schedules = plan_schedules(config, options)
    nat_rules = plan_nat(config, derived, options)
    security_rules = plan_policies(config, options)
    result = []
    specs = (
        ("address", "addresses", addresses, _address),
        ("address_group", "address_groups", groups, _members),
        ("service", "services", services, _service),
        ("service_group", "service_groups", service_groups, _members),
        ("schedule", "schedules", schedules, _schedule),
    )
    for family, attribute, sources, compare in specs:
        result.extend(_classify(target, family, attribute, item, compare, device, decisions)
                      for item in sources if item.target_name and item.status.value == "SUPPORTED")
    for route in _plan_target_route_collisions(config, derived, decisions, target, device):
        result.append(route)
    result.extend(_plan_target_nat_collisions(nat_rules, target, device))
    result.extend(_plan_target_security_rule_collisions(security_rules, target, device))
    return tuple(sorted(result, key=lambda item: (item["family"], item["source_vdom"], item["source_name"])))


def _plan_target_route_collisions(config, derived, decisions, target, device):
    from .routing import plan_routes

    planned = plan_routes(config, decisions.to_options(), derived)
    if not planned:
        return ()
    routers = [router for router in getattr(target.config, "virtual_routers", ())
               if router.name and _device(router) == device]
    result = []
    for route in planned:
        if not route.target_name or not route.destination or not route.virtual_router:
            continue
        existing = [entry for router in routers if router.name == route.virtual_router
                    for entry in (router.static_routes or ())
                    if entry.destination == route.destination]
        if not existing:
            continue
        if len(existing) != 1:
            status = "AMBIGUOUS"
            target_name = existing[0].name
        else:
            current = existing[0]
            nexthop = current.nexthop_ip_address or current.nexthop
            explicit = current.explicit_fields or set()
            def same_field(name, expected, actual):
                return (actual is None and expected is None and name not in explicit) or (
                    name in explicit and str(actual) == str(expected))
            same = (current.name == route.target_name
                    and same_field("destination", route.destination, current.destination)
                    and same_field("nexthop_type", route.nexthop_type, current.nexthop_type)
                    and same_field("nexthop_ip_address", route.nexthop, nexthop)
                    and same_field("interface", route.interface, current.interface)
                    and same_field("admin_distance", route.admin_distance, current.admin_distance))
            status = "EXACT_MATCH" if same else "NAME_CONFLICT"
            target_name = current.name
        result.append({"status": status, "family": "static_route", "source_name": route.source_name,
            "source_vdom": route.source_vdom or "root", "target_name": target_name,
            "destination": route.destination})
    return result


def _plan_target_nat_collisions(planned, target, device):
    result = []
    records = [item for item in getattr(target.config, "nat_rules", ())
               if item.name and _device(item) == device]
    for rule in planned:
        if not rule.target_name:
            continue
        same_name = [item for item in records if item.name == rule.target_name
                     and (not rule.target_vsys or not item.scope or item.scope.vsys == rule.target_vsys)]
        if len(same_name) > 1:
            status, target_name = "AMBIGUOUS", same_name[0].name
        elif same_name:
            item = same_name[0]
            explicit = item.explicit_fields or set()
            pairs = (("from_zones", rule.from_zones, item.from_zones),
                     ("to_zones", rule.to_zones, item.to_zones),
                     ("source", rule.source_addresses, item.source),
                     ("destination", rule.destination_addresses, item.destination),
                     ("service", rule.service, item.service), ("to_interface", rule.to_interface, item.to_interface))
            def same_field(field, expected, actual):
                if isinstance(expected, tuple):
                    return (actual is None and not expected and field not in explicit) or (
                        field in explicit and tuple(actual or ()) == expected)
                return ((actual is None and expected is None and field not in explicit)
                        or (field in explicit and actual == expected))
            same = all(same_field(field, expected, actual) for field, expected, actual in pairs)
            same = same and rule.source_translation is None and rule.destination_translation is None \
                and item.source_translation is None and item.destination_translation is None
            status, target_name = ("EXACT_MATCH" if same else "NAME_CONFLICT"), item.name
        else:
            target_name = None
            overlap = [item for item in records
                if (not rule.target_vsys or not item.scope or item.scope.vsys == rule.target_vsys)
                and rule.from_zones and item.from_zones and set(rule.from_zones) & set(item.from_zones)
                and rule.to_zones and item.to_zones and set(rule.to_zones) & set(item.to_zones)
                and rule.source_addresses and item.source and set(rule.source_addresses) & set(item.source)
                and rule.destination_addresses and item.destination and set(rule.destination_addresses) & set(item.destination)
                and rule.service and item.service == rule.service]
            if not overlap:
                continue
            status, target_name = "AMBIGUOUS", overlap[0].name
        result.append({"status": status, "family": "nat_rule", "source_name": rule.source_name,
            "source_vdom": rule.source_vdom or "root", "target_name": target_name})
    return result


def _plan_target_security_rule_collisions(planned, target, device):
    result = []
    records = [item for item in getattr(target.config, "security_rules", ())
               if item.name and _device(item) == device]
    fields = (("from_zones", "from_zones"), ("to_zones", "to_zones"), ("sources", "source"),
              ("destinations", "destination"), ("services", "service"), ("schedule", "schedule"),
              ("action", "action"))
    for rule in planned:
        if not rule.target_name:
            continue
        matches = [item for item in records if item.name == rule.target_name
                   and (not rule.target_vsys or not item.scope or item.scope.vsys == rule.target_vsys)]
        if not matches:
            continue
        status = "AMBIGUOUS" if len(matches) > 1 else "NAME_CONFLICT"
        if len(matches) == 1:
            item = matches[0]
            explicit = item.explicit_fields or set()
            same = True
            for source_field, target_field in fields:
                expected = getattr(rule, source_field)
                actual = getattr(item, target_field)
                if isinstance(expected, tuple):
                    same &= (target_field in explicit and tuple(actual or ()) == expected) if expected else (
                        actual is None and target_field not in explicit)
                else:
                    same &= (target_field in explicit and actual == expected) if expected is not None else (
                        actual is None and target_field not in explicit)
            same &= (item.negate_source == ("yes" if rule.negate_source else None)
                     and item.negate_destination == ("yes" if rule.negate_destination else None)
                     and item.disabled == ("yes" if rule.disabled else None))
            if same:
                status = "EXACT_MATCH"
        result.append({"status": status, "family": "security_rule", "source_name": rule.source_name,
            "source_vdom": rule.source_vdom or "root", "target_name": matches[0].name})
    return result


def mark_target_name_collisions(plan, classifications, target_findings=()):
    """Keep target conflicts and ambiguous target state out of rendering."""
    fields = {"address": "addresses", "address_group": "address_groups", "service": "services",
              "service_group": "service_groups", "schedule": "schedules", "static_route": "static_routes",
              "nat_rule": "nat_rules", "security_rule": "security_rules"}
    blocked = {(item["family"], item["source_vdom"], item["source_name"]): item
               for item in classifications if item["status"] in {"NAME_CONFLICT", "AMBIGUOUS"}}
    for family, attribute in fields.items():
        values = []
        for item in getattr(plan, attribute):
            finding = blocked.get((family, item.source_vdom or "root", item.source_name))
            if finding:
                warning = f"Target object {finding['target_name']!r} requires review: {finding['status']}"
                item = replace(item, status=PANMigrationStatus.MANUAL_REVIEW,
                               warnings=tuple(dict.fromkeys((*(item.warnings or ()), warning))))
            values.append(item)
        plan = replace(plan, **{attribute: tuple(values)})
    blocked_vdoms = set()
    for finding in target_findings:
        if finding.severity != "error":
            continue
        try:
            source_vdom = json.loads(finding.decision_key)[0]
        except (TypeError, ValueError, json.JSONDecodeError, IndexError):
            continue
        blocked_vdoms.add(source_vdom)
    if blocked_vdoms:
        for attribute in ("addresses", "address_groups", "services", "service_groups", "schedules",
                          "zones", "static_routes", "security_rules", "nat_rules"):
            values = []
            for item in getattr(plan, attribute):
                if item.source_vdom in blocked_vdoms and item.status == PANMigrationStatus.SUPPORTED:
                    item = replace(item, status=PANMigrationStatus.MANUAL_REVIEW,
                        warnings=tuple(dict.fromkeys((*(item.warnings or ()),
                            "Target evidence conflict blocks rendering for this VDOM."))))
                values.append(item)
            plan = replace(plan, **{attribute: tuple(values)})
    return plan
