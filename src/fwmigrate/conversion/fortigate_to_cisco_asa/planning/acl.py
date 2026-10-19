"""ASA extended ACL planning with source order and interface scope retained."""

from collections import defaultdict

from .naming import decision_key, item_key, target_name
from ..models import ASAPlanItem


def _enabled(value):
    return isinstance(value, str) and value.casefold() in {"enable", "enabled", "yes", "true"}


def _interface_names(source, vdom, requested):
    all_names = [item.name for item in source.interfaces if (item.vdom or "root") == vdom]
    if any(name.casefold() == "any" for name in requested or ()):
        return all_names, []
    zones = {zone.name: tuple(zone.members or ()) for zone in source.zones if (zone.vdom or "root") == vdom}
    result, issues = [], []
    for name in requested or ():
        members = zones.get(name, (name,) if name in all_names else ())
        if not members:
            issues.append("SOURCE_INTERFACE_REFERENCE_UNRESOLVED")
        result.extend(members)
    return list(dict.fromkeys(result)), issues


def _address_operand(name, address_names, groups):
    if name.casefold() == "all":
        return "any"
    if name.casefold() == "none":
        raise ValueError
    target = address_names[name]
    return f"{'object-group' if name in groups else 'object'} {target}"


def _service_leaves(name, vdom, services, groups, path=()):
    if name.casefold() in {"all", "any"}:
        return [("ip", None, None)]
    if name in path:
        raise ValueError
    if name in services:
        item = services[name]
        protocol = (item.protocol or "").casefold()
        if protocol not in {"tcp", "udp", "icmp"}:
            raise ValueError
        if item.source_port:
            raise ValueError
        return [(protocol, item.port, item.icmp_type)]
    if name in groups:
        rows = []
        for child in groups[name].members or ():
            rows.extend(_service_leaves(child, vdom, services, groups, (*path, name)))
        return rows
    raise ValueError


def _port_clause(port):
    if not port:
        return ""
    value = str(port)
    if "-" in value:
        first, last = value.split("-", 1)
        if not first.isdecimal() or not last.isdecimal() or not 0 <= int(first) <= int(last) <= 65535:
            raise ValueError
        return f" range {first} {last}"
    if not value.isdecimal() or not 0 <= int(value) <= 65535:
        raise ValueError
    return f" eq {value}"


def plan_policies(source, derived, options, address_names, service_names, *, target_evidence=None):
    vdom = options.source_vdom
    groups = {item.name for item in source.address_groups if (item.vdom or "root") == vdom}
    services = {item.name: item for item in derived.services.services if item.vdom == vdom}
    service_groups = {item.name: item for item in derived.services.groups if item.vdom == vdom}
    per_interface = defaultdict(list)
    items = []
    for policy in sorted((p for p in source.policies if (p.vdom or "root") == vdom),
                         key=lambda row: (row.policy_id is None, row.policy_id or 0)):
        source_name = str(policy.policy_id if policy.policy_id is not None else policy.name or "unknown")
        key = item_key(vdom, "policy", source_name)
        blockers, dependencies = [], []
        try:
            if policy.srcaddr6 or policy.dstaddr6 or _enabled(policy.srcaddr6_negate) or _enabled(policy.dstaddr6_negate):
                raise ValueError("IPV6_POLICY_UNSUPPORTED")
            if not policy.srcaddr or not policy.dstaddr or not policy.service:
                raise ValueError("POLICY_MATCH_FIELDS_UNVERIFIED")
            for field in ("srcaddr_negate", "dstaddr_negate", "service_negate", "utm_status",
                          "nat64", "nat46", "natinbound", "natoutbound"):
                value = getattr(policy, field)
                if value is None:
                    raise ValueError(f"POLICY_{field.upper()}_EVIDENCE_REQUIRED")
                if value != "disable":
                    raise ValueError(f"POLICY_{field.upper()}_UNSUPPORTED")
            if policy.nat is None:
                raise ValueError("POLICY_NAT_EVIDENCE_REQUIRED")
            if policy.nat not in {"disable", "enable"}:
                raise ValueError("POLICY_NAT_STATE_UNSUPPORTED")
            if policy.natip is not None or policy.poolname6:
                raise ValueError("POLICY_TRANSLATION_CONTROLS_UNSUPPORTED")
            if policy.nat == "disable" and (policy.poolname or any(
                getattr(policy, field) not in {None, "disable"}
                for field in ("ippool", "fixedport", "port_preserve")
            )):
                raise ValueError("POLICY_TRANSLATION_CONTROLS_UNSUPPORTED")
            if not policy.dstintf or any(name.casefold() != "any" for name in policy.dstintf):
                raise ValueError("POLICY_EGRESS_CONSTRAINT_UNREPRESENTABLE")
            if not policy.srcintf or policy.action is None or policy.status is None or policy.schedule is None:
                raise ValueError("POLICY_EXPLICIT_MATCH_OR_STATE_REQUIRED")
            if policy.action.casefold() not in {"accept", "deny"}:
                raise ValueError("POLICY_ACTION_UNSUPPORTED")
            if policy.status.casefold() not in {"enable", "enabled", "disable", "disabled"}:
                raise ValueError("POLICY_STATE_UNSUPPORTED")
            if policy.logtraffic is None or policy.logtraffic.casefold() != "disable":
                raise ValueError("POLICY_LOGGING_SEMANTICS_UNVERIFIED")
            if any((policy.internet_service, policy.internet_service_name, policy.internet_service_group,
                    policy.internet_service_custom, policy.internet_service_src,
                    policy.internet_service_src_name, policy.internet_service_src_group,
                    policy.internet_service_src_custom, policy.users, policy.groups, policy.vpntunnel,
                    policy.utm_status, policy.profile_group, policy.profile_type,
                    policy.profile_protocol_options, policy.av_profile, policy.ips_sensor,
                    policy.application_list, policy.webfilter_profile, policy.dnsfilter_profile,
                    policy.ssl_ssh_profile)):
                raise ValueError("POLICY_IDENTITY_OR_INSPECTION_UNSUPPORTED")
            if policy.raw_extra:
                raise ValueError("POLICY_UNMODELED_SOURCE_SETTINGS")
            ingress, interface_issues = _interface_names(source, vdom, policy.srcintf)
            blockers.extend(interface_issues)
            if not ingress:
                raise ValueError("POLICY_INGRESS_INTERFACE_UNRESOLVED")
            src = [_address_operand(name, address_names, groups) for name in policy.srcaddr]
            dst = [_address_operand(name, address_names, groups) for name in policy.dstaddr]
            service_rows = []
            for name in policy.service:
                service_rows.extend(_service_leaves(name, vdom, services, service_groups))
            if len(src) * len(dst) * len(service_rows) * len(ingress) > 256:
                raise ValueError("POLICY_ACE_EXPANSION_LIMIT_EXCEEDED")
            for source_name_addr in policy.srcaddr:
                if source_name_addr.casefold() != "all":
                    dependencies.append(item_key(vdom, "address_group" if source_name_addr in groups else "address", source_name_addr))
            for destination_name_addr in policy.dstaddr:
                if destination_name_addr.casefold() != "all":
                    dependencies.append(item_key(vdom, "address_group" if destination_name_addr in groups else "address", destination_name_addr))
            for service_name in policy.service:
                if service_name.casefold() not in {"all", "any"}:
                    dependencies.append(item_key(vdom, "service_group" if service_name in service_groups else "service", service_name))
            if str(policy.schedule).casefold() != "always":
                schedule_key = item_key(vdom, "schedule", policy.schedule)
                dependencies.append(schedule_key)
            action = "permit" if policy.action.casefold() == "accept" else "deny"
            inactive = " inactive" if policy.status.casefold() in {"disable", "disabled"} else ""
            schedule = "" if str(policy.schedule).casefold() == "always" else f" time-range {target_name('schedule', vdom, policy.schedule)}"
            commands = []
            for ingress_name in ingress:
                mapping = options.interfaces.get(vdom, {}).get(ingress_name)
                if mapping is None:
                    blockers.append("TARGET_INTERFACE_MAPPING_REQUIRED")
                    continue
                acl_name = target_name("interface", vdom, ingress_name)
                for proto, port, icmp_type in service_rows:
                    for source_operand in src:
                        for destination_operand in dst:
                            suffix = f" {icmp_type}" if proto == "icmp" and icmp_type is not None else _port_clause(port) if proto in {"tcp", "udp"} else ""
                            commands.append(f"access-list {acl_name} extended {action} {proto} {source_operand} {destination_operand}{suffix}{schedule}{inactive}")
                per_interface[ingress_name].append((policy.policy_id or 0, key))
            if policy.policy_id is None:
                blockers.append("POLICY_ORDER_UNAVAILABLE")
            if policy.nat and policy.nat.casefold() in {"enable", "enabled", "yes", "true"}:
                nat_key = item_key(vdom, "nat", source_name)
                dependencies.append(nat_key)
            items.append(ASAPlanItem(key, "policy", vdom, source_name, "",
                                     (("commands", tuple(commands)),), tuple(dict.fromkeys(dependencies)),
                                     tuple(dict.fromkeys(blockers)), int(policy.policy_id or 0)))
        except (KeyError, ValueError) as exc:
            code = str(exc) if str(exc) else "POLICY_MATCH_UNSUPPORTED"
            blockers.append(code)
            items.append(ASAPlanItem(key, "policy", vdom, source_name, "", blockers=tuple(dict.fromkeys(blockers)),
                                     source_order=int(policy.policy_id or 0)))

    for interface in source.interfaces:
        if (interface.vdom or "root") != vdom:
            continue
        nameif = options.interfaces.get(vdom, {}).get(interface.name)
        acl_name = target_name("interface", vdom, interface.name)
        dependencies = [item_key(vdom, "interface", interface.name)]
        dependencies.extend(key for _, key in per_interface.get(interface.name, ()))
        default_key = item_key(vdom, "default_behavior", interface.name)
        commands = (f"access-list {acl_name} extended deny ip any any",)
        items.append(ASAPlanItem(default_key, "default_behavior", vdom, interface.name, acl_name,
                                 (("commands", commands),), tuple(dict.fromkeys(dependencies))))
        blockers = []
        if target_evidence is None or "acl_bindings" not in target_evidence.get("complete_families", ()):
            blockers.append("TARGET_ACL_BINDING_SNAPSHOT_REQUIRED")
        elif target_evidence.get("existing_bindings", {}).get(nameif.nameif if nameif else ""):
            blockers.append("EXISTING_ACCESS_GROUP_BINDING_CONFLICT")
        bind_dependencies = tuple(dict.fromkeys((*dependencies, default_key)))
        items.append(ASAPlanItem(item_key(vdom, "acl_binding", interface.name), "acl_binding", vdom,
                                 interface.name, acl_name,
                                 (("commands", (f"access-group {acl_name} in interface {nameif.nameif}",) if nameif and not blockers else ()),),
                                 bind_dependencies, tuple(blockers)))
    return items
