"""FortiGate security-policy planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedSecurityRule


def plan_policies(source: Any, options: Any):
    result = []
    for policy in getattr(source, "policies", ()):
        warnings = []
        from_zones = _zones(policy.srcintf, policy.vdom, options, warnings)
        to_zones = _zones(policy.dstintf, policy.vdom, options, warnings)
        if policy.service_negate in {"enable", "yes", "1"}:
            warnings.append("service negation is unsupported")
        if policy.users or policy.groups:
            warnings.append("user and group matching requires manual review")
        if policy.internet_service or policy.internet_service_name or policy.internet_service_group or policy.internet_service_custom:
            warnings.append("Internet Service matching is unsupported")
        if policy.vpntunnel:
            warnings.append("VPN policy action requires manual review")
        if any(getattr(policy, field, None) for field in ("utm_status", "profile_group", "av_profile", "ips_sensor", "webfilter_profile", "ssl_ssh_profile")):
            warnings.append("FortiGate inspection settings are not mapped")
        action = {"accept": "allow", "deny": "deny"}.get((policy.action or "").lower())
        if action is None:
            warnings.append("unsupported or missing policy action")
        status = PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.PARTIAL
        if not from_zones or not to_zones:
            status = PANMigrationStatus.MANUAL_REVIEW
        result.append(PlannedSecurityRule(
            source_vdom=policy.vdom, source_kind="policy", source_object_type="security_rule",
            source_name=policy.name or str(policy.policy_id), source_policy_id=policy.policy_id,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(policy.vdom), "vsys", None),
            target_name=policy.name or str(policy.policy_id),
            status=status, warnings=tuple(warnings), from_zones=from_zones, to_zones=to_zones,
            sources=tuple(policy.srcaddr or policy.srcaddr6), destinations=tuple(policy.dstaddr or policy.dstaddr6),
            services=tuple(policy.service), schedule=policy.schedule, action=action,
            negate_source=getattr(policy, "srcaddr_negate", None) in {"enable", "yes", "1"},
            negate_destination=getattr(policy, "dstaddr_negate", None) in {"enable", "yes", "1"},
            disabled=getattr(policy, "status", None) in {"disable", "disabled"},
            description=getattr(policy, "comments", None),
        ))
    return tuple(result)


def _zones(names, vdom, options, warnings):
    result = []
    for name in names:
        mapping = _interface_mapping(options, vdom, name)
        if mapping and mapping.target_zone:
            result.append(mapping.target_zone)
        else:
            warnings.append(f"missing target zone mapping for {name!r}")
    return tuple(result)


def _interface_mapping(options, vdom, name):
    return getattr(options, "interfaces", {}).get(vdom or "root", {}).get(name)
