"""PAN-OS ordered L3/L4 policies with provable ASA ingress and egress behavior."""

from ipaddress import IPv4Address, summarize_address_range
from itertools import product
from fwmigrate.vendors.palo_alto.transform.effective_values import effective_value, RULE_REFERENCE

from .egress_zone import prove_egress_zone
from .objects import _item
from .source_scope import in_scope


def _lookup(objects, families, name):
    matches = [row for row in objects if row.family in families and row.source_name == name]
    if len(matches) != 1 or matches[0].blockers:
        raise ValueError("POLICY_OBJECT_REFERENCE_UNRESOLVED")
    return matches[0]


def _prefixes(row, by_key, path=()):
    if row.key in path or len(path) > 32 or row.blockers:
        raise ValueError("DESTINATION_OBJECT_UNPROVEN")
    values = dict(row.settings)
    if row.family == "address_group":
        result = []
        for key in row.dependencies:
            result.extend(_prefixes(by_key[key], by_key, (*path, row.key)))
            if len(result) > 1024:
                raise ValueError("DESTINATION_EXPANSION_LIMIT")
        if not result:
            raise ValueError("DESTINATION_EXPANSION_LIMIT")
        return result
    if values.get("address_type") == "prefix":
        return [values["value"]]
    if values.get("address_type") == "range":
        return [str(prefix) for prefix in summarize_address_range(IPv4Address(values["range_start"]), IPv4Address(values["range_end"]))]
    raise ValueError("DESTINATION_OBJECT_UNPROVEN")


def _services(row, by_key, path=()):
    if row.key in path or len(path) > 32 or row.blockers:
        raise ValueError("SERVICE_EXPANSION_UNPROVEN")
    if row.family == "service_group":
        result = []
        for key in row.dependencies:
            result.extend(_services(by_key[key], by_key, (*path, row.key)))
            if len(result) > 1024:
                raise ValueError("SERVICE_EXPANSION_LIMIT")
        return result
    value = dict(row.settings)
    if row.family != "service" or value.get("protocol") not in {"tcp", "udp"}:
        raise ValueError("SERVICE_PROTOCOL_UNSUPPORTED")
    return [(value["protocol"], src, dst) for src, dst in product(value.get("source_ports", (None,)), value["destination_ports"])]


def _port(value):
    if value is None:
        return ""
    return " range " + value.replace("-", " ") if "-" in value else " eq " + value


def _address(names, objects, by_key):
    if not names:
        raise ValueError("POLICY_ADDRESS_MATCH_REQUIRED")
    operands, prefixes, deps = [], [], []
    for name in names:
        matches = [row for row in objects if row.family in {"address", "address_group"} and row.source_name == name]
        if not matches and name == "any" and names == ["any"]:
            operands.append("any4")
            prefixes.append("0.0.0.0/0")
            continue
        row = _lookup(objects, {"address", "address_group"}, name)
        operands.append(f"{'object-group' if row.family == 'address_group' else 'object'} {row.target_name}")
        prefixes.extend(_prefixes(row, by_key))
        deps.append(row.key)
    return operands, prefixes, deps


def defaults_proven(source, selected):
    rows = [row for row in source.default_security_rules if in_scope(row, selected)]
    if len(rows) != 2 or {row.name for row in rows} != {"intrazone-default", "interzone-default"}:
        return False
    return all(row.action == "drop" and row.disabled == "no" and row.log_start == "no" and row.log_end == "no"
               and not row.raw_extra and not row.profile_setting and not row.log_setting
               and row.disable_server_response_inspection is None and row.icmp_unreachable is None for row in rows)


def plan_policies(source, selected, options, objects, interfaces, memberships, routes, routing_complete, nat_blocked, derived):
    result, previous = [], None
    by_key = {row.key: row for row in objects}
    zone_names = {name for names in memberships.values() for name in names}
    rules = sorted((row for row in source.security_rules if in_scope(row, selected)),
                   key=lambda row: ({"pre": 0, "local": 1, "post": 2}.get(row.rulebase_position, 3), row.source_order or 0))
    for order, rule in enumerate(rules):
        if rule.disabled == "yes":
            result.append(_item(rule, "inactive_policy", rule.name, blockers=("SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED",), order=order))
            continue
        blockers, deps, commands, proof = [], [], [], {}
        if previous:
            deps.append(previous)
        try:
            if (rule.disabled != "no" or rule.rule_type != "universal" or rule.raw_extra
                    or rule.action not in {"allow", "drop"} or rule.application != ["any"]
                    or rule.source_user != ["any"] or rule.category != ["any"]
                    or rule.negate_source != "no" or rule.negate_destination != "no"
                    or rule.schedule is not None or effective_value(derived, rule, "schedule") != "always"
                    or rule.log_start != "no" or rule.log_end != "no"
                    or any((rule.profile_setting, rule.log_setting, rule.source_hip, rule.destination_hip,
                            rule.disable_inspect, rule.disable_server_response_inspection, rule.icmp_unreachable,
                            rule.saas_user_list, rule.saas_tenant_list))):
                raise ValueError("POLICY_APP_ID_INSPECTION_STATE_SCHEDULE_OR_LOGGING_UNSUPPORTED")
            if nat_blocked:
                raise ValueError("ACTIVE_OR_UNKNOWN_NAT_BLOCKS_POLICY_EQUIVALENCE")
            if not rule.from_zones or not rule.to_zones:
                raise ValueError("POLICY_ZONE_MATCH_MUST_BE_EXPLICIT")
            from_zones = zone_names if rule.from_zones == ["any"] else set(rule.from_zones)
            to_zones = zone_names if rule.to_zones == ["any"] else set(rule.to_zones)
            if not from_zones <= zone_names or not to_zones <= zone_names:
                raise ValueError("POLICY_ZONE_REFERENCE_UNRESOLVED")
            ingress = [row for name, row in interfaces.items() if set(memberships.get(name, ())) & from_zones]
            if not ingress or any(row.blockers for row in ingress):
                raise ValueError("POLICY_INGRESS_UNPROVEN")
            src, _, src_deps = _address(rule.source, objects, by_key)
            dst, prefixes, dst_deps = _address(rule.destination, objects, by_key)
            deps.extend((*src_deps, *dst_deps))
            proven = {prove_egress_zone(prefix, routes, routing_complete=routing_complete) for prefix in prefixes}
            if rule.to_zones != ["any"] and (None in proven or len(proven) != 1 or not proven <= to_zones):
                raise ValueError("DESTINATION_ZONE_MATCH_NOT_PROVEN_FOR_ENTIRE_RANGE")
            # Security-level checks precede ACLs; unknown egress needs both explicit permissions.
            possible = zone_names if None in proven else proven
            for incoming in ingress:
                incoming_values = dict(incoming.settings)
                for outgoing in interfaces.values():
                    outgoing_values = dict(outgoing.settings)
                    if outgoing_values.get("source_zone") not in possible:
                        continue
                    if incoming.key == outgoing.key and not options.permit_intra_interface:
                        raise ValueError("ASA_INTRA_INTERFACE_PERMISSION_REQUIRED")
                    if (incoming.key != outgoing.key and incoming_values.get("security_level") == outgoing_values.get("security_level")
                            and not options.permit_inter_interface):
                        raise ValueError("ASA_SAME_SECURITY_PERMISSION_REQUIRED")
            service_values = []
            if rule.service == ["any"] and not any(row.source_name == "any" for row in objects if row.family in {"service", "service_group"}):
                raise ValueError("ONLY_EXPLICIT_TCP_UDP_SERVICES_SUPPORTED")
            else:
                for name in rule.service or ():
                    row = _lookup(objects, {"service", "service_group"}, name)
                    deps.append(row.key)
                    service_values.extend(_services(row, by_key))
                    if len(service_values) > options.ace_limit:
                        raise ValueError("POLICY_ACE_EXPANSION_LIMIT")
            count = len(ingress) * len(src) * len(dst) * len(service_values)
            if not 0 < count <= options.ace_limit:
                raise ValueError("POLICY_ACE_EXPANSION_LIMIT")
            for interface, (protocol, source_port, destination_port), source_operand, destination_operand in product(ingress, service_values, src, dst):
                nameif = dict(interface.settings)["nameif"]
                action = "permit" if rule.action == "allow" else "deny"
                commands.append(f"access-list PAN_{nameif} extended {action} {protocol} {source_operand}{_port(source_port)} {destination_operand}{_port(destination_port)}")
            deps.extend(row.key for row in ingress)
            proof = {"egress_zones": tuple(sorted(proven - {None})), "destination_prefixes": tuple(prefixes),
                     "destination_zone_unrestricted": rule.to_zones == ["any"], "ace_count": count,
                     "schedule_evidence": {"value": "always", "origin": "PANOS_DEFAULT", "version": source.source_version, "reference": RULE_REFERENCE}}
        except (ValueError, KeyError, RecursionError) as exc:
            blockers.append(str(exc) if isinstance(exc, ValueError) else "POLICY_REFERENCE_CYCLE_OR_UNRESOLVED")
        item = _item(rule, "policy", f"rule_{order + 1}", (("commands", tuple(commands)), *proof.items()), deps, blockers, order)
        result.append(item)
        previous = item.key
    return result
