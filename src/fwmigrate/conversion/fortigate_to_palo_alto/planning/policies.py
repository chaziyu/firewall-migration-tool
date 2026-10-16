"""FortiGate security-policy planning for Palo Alto."""

from typing import Any
import hashlib
import json

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedSecurityRule
from fwmigrate.conversion.fortigate_to_palo_alto.planning.services import service_target
from fwmigrate.vendors.fortigate.fortios.predefined_services import is_predefined_service_reference
from fwmigrate.vendors.fortigate.transform.effective_values import effective_value
from .addresses import address_references, explicit_all_vdoms, vip_group_addresses


INSPECTION_FIELDS = ('utm_status', 'profile_group', 'av_profile', 'ips_sensor', 'webfilter_profile',
    'ssl_ssh_profile', 'inspection_mode', 'profile_type', 'profile_protocol_options', 'application_list', 'dnsfilter_profile')


def _requires_profile_group(policy):
    return policy.utm_status not in {None, 'disable'} or any(getattr(policy, field, None)
        for field in INSPECTION_FIELDS[1:] if field not in {'ssl_ssh_profile', 'profile_protocol_options'})


def inspection_design_groups(source):
    groups = {}
    for policy in source.policies:
        if not _requires_profile_group(policy):
            continue
        facts = {field: getattr(policy, field, None) for field in INSPECTION_FIELDS if getattr(policy, field, None) is not None}
        identity = f'{policy.vdom or "root"}/' + hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()[:16]
        group = groups.setdefault(identity, {'identity': identity, 'message': '; '.join(f'{key}={value}' for key, value in facts.items()), 'member_keys': []})
        group['member_keys'].append(str(policy.policy_id) if policy.policy_id is not None else policy.name)
    return list(groups.values())


def policy_inspection_key(policy):
    facts = {field: getattr(policy, field, None) for field in INSPECTION_FIELDS if getattr(policy, field, None) is not None}
    return f'{policy.vdom or "root"}/' + hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()[:16]


def ipv6_match_warnings(policy):
    if not any(getattr(policy, field, None) is not None for field in ("srcaddr6", "dstaddr6")):
        return ()
    return ("IPv6 policy matching is unsupported; IPv4 and IPv6 evidence requires manual design",
            *(f"explicit source {field} = {getattr(policy, field, None)!r}"
              for field in ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6")))


def plan_policies(source: Any, options: Any, derived: Any = None, *, explicit_all=None):
    result = []
    if explicit_all is None:
        explicit_all = explicit_all_vdoms(source)
    from ..target.profile import policy_identity_groups
    settings = getattr(options, 'conversion_settings', {})
    eligible = {(group['source_vdom'], group['identity']) for group in policy_identity_groups(source)}
    if (any((vdom, key) not in eligible for vdom, values in settings.get('identity_mappings', {}).items() for key in values)
            or set(settings.get('identity_prerequisites', ())) - {vdom for vdom, _ in eligible}):
        raise ValueError('Identity mappings and prerequisites must select current source identities')
    explicit_services = {(item.vdom, item.name) for item in (
        *getattr(getattr(derived, "services", None), "services", ()),
        *getattr(getattr(derived, "services", None), "groups", ()),
    )}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(source, "zones", ())}
    for policy in getattr(source, "policies", ()):
        warnings = list(ipv6_match_warnings(policy))
        destinations, group_warnings = vip_group_addresses(source, policy.vdom, policy.dstaddr or ())
        warnings.extend(group_warnings)
        ipv6_configured = bool(warnings)
        if policy.srcintf is None or policy.dstintf is None:
            warnings.append("policy interface match is not explicit in the source")
        if policy.srcaddr is None and policy.srcaddr6 is None:
            warnings.append("policy source address match is not explicit in the source")
        if policy.dstaddr is None and policy.dstaddr6 is None:
            warnings.append("policy destination address match is not explicit in the source")
        if policy.service is None:
            warnings.append("policy service match is not explicit in the source")
        service_names = {name for vdom, name in explicit_services if vdom == policy.vdom}
        services = tuple(service_target(name, service_names, getattr(options, "service_names", {}).get(policy.vdom, {})) for name in policy.service or ())
        applications = ("any",)
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
        if policy.srcaddr_negate in {"enable", "yes", "1"} and policy.dstaddr_negate in {"enable", "yes", "1"}:
            warnings.append("negating both IPv4 address selectors would permit IPv6 matching on PAN-OS")
        identity_keys = [f'{kind}/{name}' for kind, names in (('user', policy.users), ('group', policy.groups)) for name in names or ()]
        identity_map = settings.get('identity_mappings', {}).get(policy.vdom or 'root', {})
        source_users = tuple(dict.fromkeys(identity_map[key] for key in identity_keys if key in identity_map))
        if identity_keys and (any(key not in identity_map for key in identity_keys)
                or (policy.vdom or 'root') not in settings.get('identity_prerequisites', ())):
            warnings.append("user and group matching requires manual review")
        if any(getattr(policy, field) not in {None, "disable"}
               for field in ("internet_service", "internet_service_src")) or any(
            getattr(policy, field) for field in (
                "internet_service_name", "internet_service_group", "internet_service_custom",
                "internet_service_src_name", "internet_service_src_group", "internet_service_src_custom",
            )
        ):
            warnings.append("Internet Service matching is unsupported")
        if policy.vpntunnel:
            warnings.append("VPN policy action requires manual review")
        profile_group = getattr(options, 'conversion_settings', {}).get('security_profiles', {}).get(policy_inspection_key(policy))
        if _requires_profile_group(policy) and not profile_group:
            warnings.append("FortiGate inspection settings are not mapped")
        if policy.ssl_ssh_profile and policy.ssl_ssh_profile != 'no-inspection':
            warnings.append('SSL/SSH inspection requires a separate target decryption design; a security profile group does not replace it')
        if policy.profile_protocol_options:
            warnings.append('Protocol options require separate verified target semantics')
        if policy.per_ip_shaper:
            warnings.append("FortiGate traffic shaping is not mapped")
        if policy.srcaddr6_negate not in {None, "disable"} or policy.dstaddr6_negate not in {None, "disable"}:
            warnings.append("IPv6 address negation requires manual review")
        log_end = {"all": "yes", "disable": "no"}.get(policy.logtraffic)
        log_start = None
        if policy.logtraffic not in {None, "all", "disable"}:
            warnings.append(f"policy logging {policy.logtraffic!r} requires manual target semantics")
        if policy.logtraffic == "disable":
            log_start = "no"
        for key in policy.raw_extra:
            if key not in {"uuid", "global-label", "label"}:
                warnings.append(f"unclassified policy setting {key!r} requires manual review")
        action_value = policy.action if policy.action is not None else effective_value(derived, policy.vdom, 'policy', policy.policy_id, 'action')
        action = {"accept": "allow", "deny": "deny"}.get((action_value or "").lower())
        if action is None:
            warnings.append("unsupported or missing policy action")
        status = PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.PARTIAL
        if not from_zones or not to_zones:
            status = PANMigrationStatus.MANUAL_REVIEW
        if ipv6_configured:
            status = PANMigrationStatus.UNSUPPORTED
        result.append(PlannedSecurityRule(
            source_vdom=policy.vdom, source_kind="policy", source_object_type="security_rule",
            source_name=policy.name or str(policy.policy_id), source_policy_id=policy.policy_id,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(policy.vdom), "vsys", None),
            target_name=policy.name or str(policy.policy_id),
            status=status, warnings=tuple(warnings), from_zones=from_zones, to_zones=to_zones,
            sources=address_references(source, policy.vdom, policy.srcaddr or (), explicit_all=explicit_all),
            destinations=address_references(source, policy.vdom, destinations, explicit_all=explicit_all),
            services=services, applications=applications,
            schedule=None if policy.schedule == "always" else policy.schedule, action=action,
            negate_source=getattr(policy, "srcaddr_negate", None) in {"enable", "yes", "1"},
            negate_destination=getattr(policy, "dstaddr_negate", None) in {"enable", "yes", "1"},
            disabled=getattr(policy, "status", None) in {"disable", "disabled"},
            description=getattr(policy, "comments", None),
            log_start=log_start, log_end=log_end,
            profile_group=profile_group,
            source_users=source_users,
        ))
    return tuple(result)


def _zones(names, vdom, options, warnings, zone_names=()):
    if "any" in names:
        if len(names) != 1:
            warnings.append("mixed wildcard and named policy interfaces require manual review")
            return ()
        return ("any",)
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
