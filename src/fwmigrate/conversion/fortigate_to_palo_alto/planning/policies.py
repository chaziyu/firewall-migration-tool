"""FortiGate security-policy planning for Palo Alto."""

from typing import Any

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedSecurityRule
from fwmigrate.conversion.fortigate_to_palo_alto.planning.services import service_target
from fwmigrate.vendors.fortigate.fortios.predefined_services import is_predefined_service_reference


def plan_policies(source: Any, options: Any, derived: Any = None):
    result = []
    explicit_services = {(item.vdom, item.name) for item in (
        *getattr(getattr(derived, "services", None), "services", ()),
        *getattr(getattr(derived, "services", None), "groups", ()),
    )}
    explicit_addresses = {(item.vdom, item.name) for item in getattr(source, "addresses", ())}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(source, "zones", ())}
    for policy in getattr(source, "policies", ()):
        warnings = []
        if policy.srcintf is None or policy.dstintf is None:
            warnings.append("policy interface match is not explicit in the source")
        if policy.srcaddr is None and policy.srcaddr6 is None:
            warnings.append("policy source address match is not explicit in the source")
        if policy.dstaddr is None and policy.dstaddr6 is None:
            warnings.append("policy destination address match is not explicit in the source")
        if policy.service is None:
            warnings.append("policy service match is not explicit in the source")
        service_names = {name for vdom, name in explicit_services if vdom == policy.vdom}
        services = tuple(service_target(name, service_names) for name in policy.service or ())
        applications = ()
        if "PING" in (policy.service or ()) and "PING" not in service_names:
            if len(policy.service or ()) == 1:
                services, applications = ("any",), ("ping",)
            else:
                warnings.append("PING mixed with other services requires manual application matching")
        for name in policy.service or ():
            if name not in service_names and is_predefined_service_reference(name) and name not in {"ALL", "HTTP", "HTTPS", "DNS", "PING"}:
                warnings.append(f"predefined service {name!r} requires manual target semantics")
        from_zones = _zones(policy.srcintf or (), policy.vdom, options, warnings, zone_names)
        to_zones = _zones(policy.dstintf or (), policy.vdom, options, warnings, zone_names)
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
            sources=tuple("any" if name == "all" and (policy.vdom, name) not in explicit_addresses else name
                          for name in (policy.srcaddr or policy.srcaddr6 or ())),
            destinations=tuple("any" if name == "all" and (policy.vdom, name) not in explicit_addresses else name
                               for name in (policy.dstaddr or policy.dstaddr6 or ())),
            services=services, applications=applications,
            schedule=None if policy.schedule == "always" else policy.schedule, action=action,
            negate_source=getattr(policy, "srcaddr_negate", None) in {"enable", "yes", "1"},
            negate_destination=getattr(policy, "dstaddr_negate", None) in {"enable", "yes", "1"},
            disabled=getattr(policy, "status", None) in {"disable", "disabled"},
            description=getattr(policy, "comments", None),
        ))
    return tuple(result)


def _zones(names, vdom, options, warnings, zone_names=()):
    result = []
    for name in names:
        mapping = _interface_mapping(options, vdom, name, zone_names)
        if mapping and mapping.target_zone:
            result.append(mapping.target_zone)
        else:
            warnings.append(f"missing target zone mapping for {name!r}")
    return tuple(result)


def _interface_mapping(options, vdom, name, zone_names=()):
    vdom = vdom or "root"
    if (vdom, name) in zone_names:
        zones = getattr(options, "zones", None)
        return ((zones or {}).get(vdom, {}).get(name) if zones is not None
                else getattr(options, "interfaces", {}).get(vdom, {}).get(name))
    return getattr(options, "interfaces", {}).get(vdom, {}).get(name)
