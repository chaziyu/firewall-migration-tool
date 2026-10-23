"""Plan ordered L3/L4 PAN-OS rules into native Junos zone contexts."""

from itertools import product

from fwmigrate.vendors.palo_alto.transform.effective_values import effective_value, RULE_REFERENCE

from .source_scope import identity, in_scope
from ..models import SRXPlanItem
from ..planning.objects import _safe_name


def _lookup(rows):
    result = {}
    for row in rows:
        if row.source_name:
            result.setdefault(row.source_name, []).append(row)
    return result


def plan_policies(source, derived, selected, options, objects, zones, zone_names, nat_blocked=False):
    addresses = _lookup([row for row in objects if row.family in {"address", "address_group"}])
    services = _lookup([row for row in objects if row.family in {"service", "service_group"}])
    planned_zones = _lookup(zones)
    zone_objects = [row for row in source.zones if in_scope(row, selected)]
    available_zone_names = tuple(row.name for row in zone_objects if row.name)
    blocked_contexts = set()
    previous_by_context = {}
    result = []
    positions = {"pre": 0, "local": 1, "post": 2}
    applicable = sorted((row for row in source.security_rules if in_scope(row, selected)),
                        key=lambda row: (positions.get(row.rulebase_position, 1), row.source_order or 0))
    for order, rule in enumerate(applicable):
        blockers = []
        if rule.raw_extra or rule.profile_setting or rule.rule_type != "universal":
            blockers.append("POLICY_HAS_UNSUPPORTED_SOURCE_SEMANTICS")
        if rule.disabled == "yes":
            result.append(SRXPlanItem(
                identity(rule, "inactive_policy"), "inactive_policy", identity(rule, "scope"),
                "policy", rule.name or "(unnamed)", rule.source_path, rule.name or "(unnamed)",
                blockers=("SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED",),
                source_order=rule.source_order or order,
            ))
            continue
        if rule.disabled != "no" or rule.action not in {"allow", "deny", "drop"}:
            blockers.append("POLICY_STATE_OR_ACTION_NOT_EXPLICITLY_SUPPORTED")
        if rule.application != ["any"]:
            blockers.append("PAN_APP_ID_IS_NOT_A_JUNOS_TRANSPORT_APPLICATION")
        if rule.source_user != ["any"] or rule.category != ["any"]:
            blockers.append("POLICY_USER_OR_CATEGORY_MATCH_NOT_EXPLICITLY_ANY")
        if rule.negate_source != "no" or rule.negate_destination != "no":
            blockers.append("POLICY_NEGATED_ADDRESS_MATCH_UNSUPPORTED")
        # A configured schedule is an object reference, including the name "always".
        # Only version-verified omitted schedule behavior is unrestricted.
        schedule_verified = rule.schedule is None and effective_value(derived, rule, "schedule") == "always"
        if not schedule_verified:
            blockers.append("POLICY_SCHEDULE_UNSUPPORTED")
        if rule.log_start not in {"no", "yes"} or rule.log_end not in {"no", "yes"}:
            blockers.append("POLICY_LOGGING_MODE_UNSUPPORTED")
        if rule.log_end == "yes" and rule.action in {"deny", "drop"}:
            blockers.append("DENY_LOGGING_MAPPING_REQUIRES_REVIEW")
        from_zones = available_zone_names if rule.from_zones == ["any"] else rule.from_zones or ()
        to_zones = available_zone_names if rule.to_zones == ["any"] else rule.to_zones or ()
        if not from_zones or not to_zones or any(name not in zone_names for name in (*from_zones, *to_zones)):
            blockers.append("POLICY_ZONE_SCOPE_UNRESOLVED")
        source_values, destination_values, application_values, deps = [], [], [], []
        for names, index, values in ((rule.source, addresses, source_values),
                                     (rule.destination, addresses, destination_values),
                                     (rule.service, services, application_values)):
            if names == ["any"]:
                values.append("any")
                continue
            if not names:
                blockers.append("POLICY_MATCH_NOT_EXPLICIT")
                continue
            for name in names:
                matches = index.get(name, ())
                if len(matches) != 1:
                    blockers.append("POLICY_REFERENCE_UNRESOLVED_OR_AMBIGUOUS")
                else:
                    values.append(matches[0].target_name)
                    deps.append(matches[0].key)
                    if matches[0].blockers:
                        blockers.append("POLICY_MATCH_OBJECT_BLOCKED")
        if not application_values:
            blockers.append("POLICY_L4_SERVICE_REQUIRED")
        if nat_blocked:
            blockers.append("ACTIVE_OR_UNKNOWN_NAT_BLOCKS_POLICY_EQUIVALENCE")
        action = "permit" if rule.action == "allow" else "deny"
        pairs = product(dict.fromkeys(from_zones), dict.fromkeys(to_zones))
        for pair_index, (source_zone, destination_zone) in enumerate(pairs):
            if source_zone == destination_zone and source_zone not in zone_names:
                continue
            from_zone, to_zone = zone_names.get(source_zone), zone_names.get(destination_zone)
            if not from_zone or not to_zone:
                continue
            context = (source_zone, destination_zone)
            item_blockers = list(blockers)
            item_dependencies = list(deps)
            for name in dict.fromkeys((source_zone, destination_zone)):
                matches = planned_zones.get(name, ())
                if len(matches) != 1:
                    item_blockers.append("POLICY_ZONE_DEPENDENCY_UNRESOLVED")
                else:
                    item_dependencies.append(matches[0].key)
            if context in previous_by_context:
                item_dependencies.append(previous_by_context[context])
            if context in blocked_contexts:
                item_blockers.append("EARLIER_POLICY_IN_CONTEXT_UNSUPPORTED")
            settings = {
                "from_zone": from_zone, "to_zone": to_zone,
                "source_addresses": tuple(dict.fromkeys(source_values)),
                "destination_addresses": tuple(dict.fromkeys(destination_values)),
                "applications": tuple(dict.fromkeys(application_values)),
                "action": action, "log_start": rule.log_start == "yes", "log_end": rule.log_end == "yes",
            }
            if schedule_verified:
                settings["schedule_evidence"] = {"value": "always", "origin": "PANOS_DEFAULT",
                                                 "version": source.source_version, "reference": RULE_REFERENCE}
            result.append(SRXPlanItem(
                key=identity(rule, "policy") + f":{source_zone}:{destination_zone}",
                family="policy", source_scope=identity(rule, "scope"), source_kind="policy",
                source_name=rule.name or "(unnamed)", source_path=rule.source_path,
                target_name=_safe_name(rule.name) + (f"-{pair_index + 1}" if len(from_zones) * len(to_zones) > 1 else ""),
                settings=tuple(settings.items()), dependencies=tuple(dict.fromkeys(item_dependencies)),
                blockers=tuple(dict.fromkeys(item_blockers)), source_order=rule.source_order or order,
            ))
            previous_by_context[context] = result[-1].key
            if item_blockers:
                blocked_contexts.add(context)
        if not from_zones or not to_zones or any(name not in zone_names for name in (*from_zones, *to_zones)):
            blocked_contexts.update(product(available_zone_names, available_zone_names))
    return result
