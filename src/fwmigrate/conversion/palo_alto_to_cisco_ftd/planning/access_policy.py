"""FMC Access Control Policy rules planning."""

from fwmigrate.vendors.palo_alto.transform.effective_values import effective_value, RULE_REFERENCE

from .acp import acp_key as get_acp_key
from .objects import binding, item, operation
from .source_scope import in_scope


def defaults_proven(source, selected):
    rows = [row for row in source.default_security_rules if in_scope(row, selected)]
    return (
        len(rows) == 2
        and {row.name for row in rows} == {"intrazone-default", "interzone-default"}
        and all(
            row.action == "drop"
            and row.disabled == "no"
            and row.log_start == "no"
            and row.log_end == "no"
            and not row.raw_extra
            and not row.profile_setting
            and not row.log_setting
            and row.disable_server_response_inspection is None
            and row.icmp_unreachable is None
            for row in rows
        )
    )


def _resolve_refs(names, objects, families):
    if not names:
        raise ValueError("POLICY_MATCH_MUST_BE_EXPLICIT")
    if names == ["any"]:
        return None, []
    values, deps = [], []
    for name in names:
        matches = [
            row for row in objects
            if row.family in families and row.source_name == name
            and not dict(row.settings).get("is_source_port")
        ]
        if not matches or len(matches) != 1 or matches[0].blockers:
            raise ValueError("POLICY_OBJECT_UNRESOLVED_OR_UNSUPPORTED")
        dep_item = matches[0]
        deps.append(dep_item.key)
        fmc_type = dict(dep_item.settings).get("fmc_type", "Network")
        values.append(binding(dep_item.key, fmc_type))
    return {"objects": values}, deps


def plan_access_rules(source, derived, selected, options, domain_id, objects, traffic_blockers):
    rules = sorted(
        (row for row in source.security_rules if in_scope(row, selected)),
        key=lambda row: ({"pre": 0, "local": 1, "post": 2}.get(row.rulebase_position, 3), row.source_order or 0),
    )
    result, previous = [], None
    acp_container_key = get_acp_key(options.source_scope, options)

    for order, rule in enumerate(rules):
        if rule.disabled == "yes":
            result.append(item(rule, "inactive_policy", blockers=("SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED",), order=order))
            continue

        row = item(rule, "policy", order=order)
        blockers = list(traffic_blockers)
        deps = [previous] if previous else []
        if options.target_mode == "new":
            deps.append(acp_container_key)
        settings = ()

        try:
            if (
                rule.disabled != "no"
                or rule.rule_type != "universal"
                or rule.raw_extra
                or rule.action not in {"allow", "drop"}
                or rule.application != ["any"]
                or rule.source_user != ["any"]
                or rule.category != ["any"]
                or rule.negate_source != "no"
                or rule.negate_destination != "no"
                or rule.schedule is not None
                or effective_value(derived, rule, "schedule") != "always"
                or rule.log_start != "no"
                or rule.log_end != "no"
                or any((
                    rule.profile_setting, rule.log_setting, rule.source_hip,
                    rule.destination_hip, rule.disable_inspect,
                    rule.disable_server_response_inspection, rule.icmp_unreachable,
                    rule.saas_user_list, rule.saas_tenant_list,
                ))
            ):
                raise ValueError("POLICY_APP_ID_IDENTITY_SCHEDULE_LOGGING_OR_INSPECTION_UNSUPPORTED")

            if options.target_mode == "existing":
                raise ValueError("EXISTING_TARGET_POLICY_INSERTION_NOT_PROVEN")

            # Zones
            src_zones, src_zone_deps = _resolve_refs(rule.from_zones, objects, {"zone"})
            dst_zones, dst_zone_deps = _resolve_refs(rule.to_zones, objects, {"zone"})
            deps.extend((*src_zone_deps, *dst_zone_deps))

            # Addresses
            src_nets, src_net_deps = _resolve_refs(rule.source, objects, {"address", "address_group"})
            dst_nets, dst_net_deps = _resolve_refs(rule.destination, objects, {"address", "address_group"})
            deps.extend((*src_net_deps, *dst_net_deps))

            # Services & Ports
            src_ports = None
            if rule.service == ["any"] or rule.service == ["application-default"]:
                dst_ports, service_deps = None, []
            else:
                matched_services = []
                for s_name in rule.service:
                    candidates = [
                        m for m in objects
                        if m.family in {"service", "service_group"}
                        and m.source_name == s_name
                        and not dict(m.settings).get("is_source_port")
                    ]
                    group_matches = [m for m in candidates if m.family == "service_group"]
                    matches = group_matches if group_matches else candidates
                    if len(matches) != 1 or matches[0].blockers:
                        raise ValueError("POLICY_SERVICE_UNRESOLVED_OR_UNSUPPORTED")
                    matched_services.append(matches[0])

                # Check source-port correlation across all matched services
                src_port_keys = {
                    dict(m.settings).get("source_port_key")
                    for m in matched_services
                    if dict(m.settings).get("source_port_key")
                }
                if len(src_port_keys) > 1:
                    raise ValueError("POLICY_SERVICE_PORT_CORRELATION_CONFLICT")

                service_deps = [m.key for m in matched_services]
                dst_ports = {"objects": [binding(m.key, dict(m.settings).get("fmc_type", "ProtocolPortObject")) for m in matched_services]}
                if src_port_keys:
                    sp_key = src_port_keys.pop()
                    src_ports = {"objects": [binding(sp_key, "ProtocolPortObject")]}
                    service_deps.append(sp_key)

            deps.extend(service_deps)

            body = {
                "name": row.target_name,
                "action": "ALLOW" if rule.action == "allow" else "BLOCK",
                "enabled": True,
                "type": "AccessRule",
                "sendEventsToFMC": False,
                "logBegin": False,
                "logEnd": False,
                "logFiles": False,
            }
            if src_zones:
                body["sourceZones"] = src_zones
            if dst_zones:
                body["destinationZones"] = dst_zones
            if src_nets:
                body["sourceNetworks"] = src_nets
            if dst_nets:
                body["destinationNetworks"] = dst_nets
            if src_ports:
                body["sourcePorts"] = src_ports
            if dst_ports:
                body["destinationPorts"] = dst_ports

            path = f"/api/fmc_config/v1/domain/{domain_id}/policy/accesspolicies/{{$response_binding: {acp_container_key}.id}}/accessrules"
            settings = (
                operation(row.key, path, body, "AccessRule"),
                ("fmc_type", "AccessRule"),
                ("schedule_evidence", {
                    "value": "always",
                    "origin": "PANOS_DEFAULT",
                    "version": source.source_version,
                    "reference": RULE_REFERENCE,
                }),
            )
        except ValueError as exc:
            blockers.append(str(exc))

        result.append(item(rule, "policy", settings=settings, dependencies=deps, blockers=blockers, order=order))
        previous = row.key

    return result
