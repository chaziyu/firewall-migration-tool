"""Only explicit unrestricted-zone PAN L3/L4 rules are initially representable."""

from fwmigrate.vendors.palo_alto.transform.effective_values import effective_value, RULE_REFERENCE

from .objects import binding, item, operation
from .package import package_keys
from .source_scope import in_scope


def defaults_proven(source, selected):
    rows = [row for row in source.default_security_rules if in_scope(row, selected)]
    return (len(rows) == 2 and {row.name for row in rows} == {"intrazone-default", "interzone-default"}
        and all(row.action == "drop" and row.disabled == "no" and row.log_start == "no" and row.log_end == "no"
            and not row.raw_extra and not row.profile_setting and not row.log_setting
            and row.disable_server_response_inspection is None and row.icmp_unreachable is None for row in rows))


def _references(names, objects, families, *, allow_any=False):
    if not names:
        raise ValueError("POLICY_MATCH_MUST_BE_EXPLICIT")
    values, deps = [], []
    for name in names:
        matches = [row for row in objects if row.family in families and row.source_name == name
                   and not (row.family == "service" and row.source_kind == "PANService")]
        if matches and name == "any":
            raise ValueError("POLICY_RESERVED_REFERENCE_AMBIGUOUS")
        if not matches and allow_any and names == ["any"]:
            return ["Any"], []
        if len(matches) != 1 or matches[0].blockers:
            raise ValueError("POLICY_OBJECT_UNRESOLVED_OR_UNSUPPORTED")
        deps.append(matches[0].key)
        values.append(binding(matches[0].key))
    return values, deps


def plan_access_rules(source, derived, selected, options, objects, traffic_blockers):
    rules = sorted((row for row in source.security_rules if in_scope(row, selected)),
        key=lambda row: ({"pre": 0, "local": 1, "post": 2}.get(row.rulebase_position, 3), row.source_order or 0))
    result, previous = [], None
    for order, rule in enumerate(rules):
        if rule.disabled == "yes":
            result.append(item(rule, "inactive_policy", blockers=("SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED",), order=order))
            continue
        row = item(rule, "policy", order=order)
        blockers, deps, settings = list(traffic_blockers), [previous] if previous else [], ()
        if options.target_mode == "new":
            deps.extend(package_keys(options.source_scope))
        try:
            if rule.from_zones != ["any"] or rule.to_zones != ["any"]:
                raise ValueError("PAN_ZONE_ENFORCEMENT_AND_GATEWAY_ASSIGNMENT_UNPROVEN")
            if (rule.disabled != "no" or rule.rule_type != "universal" or rule.raw_extra
                    or rule.action not in {"allow", "drop"} or rule.application != ["any"]
                    or rule.source_user != ["any"] or rule.category != ["any"]
                    or rule.negate_source != "no" or rule.negate_destination != "no"
                    or rule.schedule is not None or effective_value(derived, rule, "schedule") != "always"
                    or rule.log_start != "no" or rule.log_end != "no"
                    or any((rule.profile_setting, rule.log_setting, rule.source_hip, rule.destination_hip,
                            rule.disable_inspect, rule.disable_server_response_inspection, rule.icmp_unreachable,
                            rule.saas_user_list, rule.saas_tenant_list))):
                raise ValueError("POLICY_APP_ID_IDENTITY_SCHEDULE_LOGGING_OR_INSPECTION_UNSUPPORTED")
            if options.target_mode == "existing":
                # shortcut: existing-layer enforcement is unproved; enable only with native layer and packet-flow fixtures.
                raise ValueError("EXISTING_TARGET_POLICY_INSERTION_NOT_PROVEN")
            src, src_deps = _references(rule.source, objects, {"address", "address_group"}, allow_any=True)
            dst, dst_deps = _references(rule.destination, objects, {"address", "address_group"}, allow_any=True)
            services, service_deps = _references(rule.service, objects, {"service_group"})
            deps.extend((*src_deps, *dst_deps, *service_deps))
            package_key, cleanup_key, _ = package_keys(options.source_scope)
            position = {"below": binding(previous)} if previous else {"above": binding(cleanup_key)}
            body = {"name": row.target_name, "layer": {"$response_binding": package_key + ".layer_uid"},
                "position": position, "source": src, "destination": dst, "service": services,
                "source-negate": False, "destination-negate": False, "service-negate": False,
                "action": "Accept" if rule.action == "allow" else "Drop", "enabled": True,
                "time": ["Any"], "vpn": "Any", "install-on": list(options.install_on) or ["Policy Targets"],
                "track": {"type": "None"}}
            settings = (operation(row.key, "add-access-rule", body, "rule_uid"),
                ("schedule_evidence", {"value": "always", "origin": "PANOS_DEFAULT",
                    "version": source.source_version, "reference": RULE_REFERENCE}))
        except ValueError as exc:
            blockers.append(str(exc))
        result.append(item(rule, "policy", settings=settings, dependencies=deps, blockers=blockers, order=order))
        previous = row.key
    return result
