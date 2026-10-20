"""One-layer Check Point Access Rule requests with source order retained."""

from collections import Counter

from ..models import CPMigrationItem
from .naming import item_key, target_name
from .objects import address_leaves, service_leaves
from .package import package_keys


def _explicit(policy, field):
    return field in set(policy.explicit_fields)


def _enabled(value):
    return isinstance(value, str) and value.casefold() in {"enable", "enabled", "yes", "true"}


def _disabled(value):
    return isinstance(value, str) and value.casefold() in {"disable", "disabled", "no", "false"}


def plan_access_rules(source, derived, vdom, options, address_names, service_names,
                      normalized_service_names, source_inventory):
    policies = [(index, row) for index, row in enumerate(source.policies)
                if (row.vdom or "root") == vdom]
    central_snat = any(
        "central-snat-map" in str(getattr(row, "source_path", "")).casefold()
        and getattr(row, "object_name", None) is not None
        for row in source_inventory
    )
    items = []
    previous_policy_key = None
    earlier_blocked = False
    policy_ids = [row.policy_id for _, row in policies if row.policy_id is not None]
    duplicate_policy_ids = {policy_id for policy_id, count in Counter(policy_ids).items() if count > 1}
    for order, policy in policies:
        source_name = str(policy.policy_id if policy.policy_id is not None else policy.name or order)
        duplicated = policy.policy_id in duplicate_policy_ids if policy.policy_id is not None else False
        key = item_key(vdom, "policy", f"{source_name}#duplicate:{order}") if duplicated else item_key(vdom, "policy", source_name)
        blockers = []
        if duplicated:
            blockers.append("POLICY_ID_DUPLICATE")
        dependencies = [previous_policy_key] if previous_policy_key else []
        if options.target_mode == "new":
            dependencies.extend(package_keys(vdom))
        body = None
        try:
            required = ("srcintf", "dstintf", "srcaddr", "dstaddr",
                        "srcaddr_negate", "dstaddr_negate", "service", "service_negate",
                        "schedule", "action", "status", "nat", "utm_status", "logtraffic")
            if any(not _explicit(policy, field) for field in required):
                raise ValueError("POLICY_EXPLICIT_MATCH_AND_STATE_REQUIRED")
            if policy.policy_id is None:
                raise ValueError("POLICY_ORDER_UNAVAILABLE")
            if (not policy.srcintf or not policy.dstintf
                    or any(not isinstance(value, str) or value.casefold() != "any"
                           for value in (*policy.srcintf, *policy.dstintf))):
                raise ValueError("POLICY_INTERFACE_CONSTRAINT_UNREPRESENTABLE")
            if not policy.srcaddr or not policy.dstaddr or not policy.service:
                raise ValueError("POLICY_MATCH_FIELDS_EMPTY_OR_UNKNOWN")
            if not isinstance(policy.action, str) or policy.action.casefold() not in {"accept", "deny"}:
                raise ValueError("POLICY_ACTION_UNSUPPORTED")
            if not (_enabled(policy.status) or _disabled(policy.status)):
                raise ValueError("POLICY_STATE_UNSUPPORTED")
            if not isinstance(policy.schedule, str) or policy.schedule.casefold() != "always":
                raise ValueError("POLICY_SCHEDULE_REQUIRES_UNVERIFIED_TIME_OBJECT")
            if _enabled(policy.nat) or any(getattr(policy, field, None) for field in ("nat64", "nat46", "natinbound", "natoutbound", "natip", "ippool", "poolname", "poolname6")):
                raise ValueError("POLICY_NAT_REMAINS_MANUAL")
            if not _disabled(policy.nat):
                raise ValueError("POLICY_NAT_STATE_UNKNOWN")
            if not isinstance(policy.logtraffic, str) or policy.logtraffic.casefold() not in {"all", "disable"}:
                raise ValueError("POLICY_TRACKING_SEMANTICS_UNSUPPORTED")
            if (_enabled(policy.utm_status) or not _disabled(policy.utm_status)):
                raise ValueError("POLICY_INSPECTION_STATE_UNSUPPORTED_OR_UNKNOWN")
            if any((policy.srcaddr6, policy.dstaddr6, policy.internet_service, policy.internet_service_name,
                    policy.internet_service_group, policy.internet_service_custom, policy.internet_service_src,
                    policy.internet_service_src_name, policy.internet_service_src_group,
                    policy.internet_service_src_custom, policy.users, policy.groups, policy.vpntunnel,
                    policy.inspection_mode, policy.profile_group, policy.profile_type,
                    policy.profile_protocol_options, policy.av_profile, policy.ips_sensor,
                    policy.application_list, policy.webfilter_profile, policy.dnsfilter_profile,
                    policy.ssl_ssh_profile, policy.per_ip_shaper)):
                raise ValueError("POLICY_IDENTITY_INSPECTION_OR_IPV6_UNSUPPORTED")
            if policy.raw_extra:
                raise ValueError("POLICY_UNMODELED_SOURCE_SETTINGS")
            for field in ("srcaddr_negate", "dstaddr_negate", "service_negate"):
                value = getattr(policy, field, None)
                if not isinstance(value, str) or value.casefold() not in {
                    "enable", "enabled", "disable", "disabled", "yes", "no", "true", "false",
                }:
                    raise ValueError(f"POLICY_{field.upper()}_UNKNOWN")
            if central_snat:
                raise ValueError("UNREPRESENTED_CENTRAL_SNAT_BLOCKS_POLICY_EXPORT")
            if options.target_mode == "existing" and (not options.policy_package or not options.access_layer or not options.install_on):
                raise ValueError("CHECKPOINT_POLICY_SCOPE_AND_INSTALL_ON_REQUIRED")
            if options.target_mode == "existing" and (options.insertion_relation != "above" or not options.insertion_anchor or options.target_cleanup_action != "Drop"):
                raise ValueError("CHECKPOINT_DROP_CLEANUP_ANCHOR_REQUIRED")

            sources, destinations, services = [], [], []
            for source_ref in policy.srcaddr:
                leaves = address_leaves(source, derived, vdom, source_ref)
                sources.extend(leaves)
            for destination_ref in policy.dstaddr:
                leaves = address_leaves(source, derived, vdom, destination_ref)
                destinations.extend(leaves)
            for service_ref in policy.service:
                services.extend(service_leaves(source, derived, vdom, service_ref, service_names,
                                               normalized_service_names))
            for _name, dependency in (*sources, *destinations, *services):
                if dependency:
                    dependencies.append(dependency)
            policy_name = target_name("rule", vdom, source_name)
            position = ({options.insertion_relation: options.insertion_anchor} if previous_policy_key is None
                        else {"below": {"$response_binding": f"{previous_policy_key}.uid"}})
            layer = options.access_layer
            if options.target_mode == "new":
                package_key, cleanup_key = package_keys(vdom)
                layer = {"$response_binding": f"{package_key}.layer_uid"}
                if previous_policy_key is None:
                    position = {"above": {"$response_binding": f"{cleanup_key}.uid"}}
            def references(rows):
                values, seen = [], set()
                for name, dependency in rows:
                    identity = dependency or name.casefold()
                    if identity in seen:
                        continue
                    seen.add(identity)
                    values.append({"$response_binding": f"{dependency}.uid"} if dependency else name)
                return values

            body = {
                "layer": layer,
                "position": position,
                "name": policy_name,
                "action": "Accept" if policy.action.casefold() == "accept" else "Drop",
                "source": references(sources),
                "destination": references(destinations),
                "service": references(services),
                "source-negate": _enabled(policy.srcaddr_negate),
                "destination-negate": _enabled(policy.dstaddr_negate),
                "service-negate": _enabled(policy.service_negate),
                "enabled": _enabled(policy.status),
                "install-on": list(options.install_on) or ["Policy Targets"],
                "time": ["Any"],
                "track": {"type": "Log" if policy.logtraffic.casefold() == "all" else "None"},
            }
        except (KeyError, ValueError) as exc:
            blockers.append(str(exc) or "POLICY_MATCH_UNSUPPORTED")
        if earlier_blocked:
            blockers.append("EARLIER_SOURCE_POLICY_REMAINS_MANUAL")
        if body and not blockers:
            operation = {
                "path": "/web_api/add-access-rule",
                "request_body_template": body,
                "response_binding": {"binding_id": f"{key}.uid", "json_pointer": "/uid", "value_type": "rule_uid"},
                "policy_context": {"package": options.policy_package, "domain": options.management_domain},
            }
            settings = (("management_operation", operation),)
        else:
            settings = ()
        item = CPMigrationItem(key, "policy", vdom, source_name,
                               target_name("rule", vdom, source_name), settings,
                               tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(blockers)), order)
        items.append(item)
        previous_policy_key = key
        earlier_blocked = earlier_blocked or bool(blockers)
    return items, central_snat

