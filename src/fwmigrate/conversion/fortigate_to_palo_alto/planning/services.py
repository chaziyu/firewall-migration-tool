"""FortiGate service planning for Palo Alto."""

from typing import Any
from dataclasses import replace

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedService, PlannedServiceGroup
from .vips import vip_port_translation, vip_service_name
from ..target.name_validation import object_description_issue


PAN_BUILTIN_SERVICES = frozenset({"any", "service-https"})


def _source_service_warnings(originals):
    if len(originals) != 1:
        return ("service source is missing or ambiguous",)
    original = originals[0]
    settings = set(original.raw_extra) - {"uuid", "color"}
    if original.proxy not in {None, "disable"}:
        settings.add("proxy")
    if getattr(original, "session_ttl", None) is not None:
        settings.add("session-ttl")
    warnings = tuple(f"service setting {name!r} requires manual target semantics" for name in sorted(settings))
    if issue := object_description_issue(getattr(original, 'comment', None)):
        warnings += (issue,)
    return warnings


def service_target(name, explicit_names, names=None):
    target = name if name in explicit_names else {"ALL": "any", "HTTPS": "service-https"}.get(name, name)
    return (names or {}).get(target, target)


def plan_services(derived: Any, options: Any = None, source: Any = None):
    result = getattr(derived, "services", None)
    if result is None:
        return (), ()
    services = []
    source_services = {}
    for original in getattr(source, "services", ()):
        source_services.setdefault((original.vdom or "root", original.name), []).append(original)
    source_groups = {}
    for original in getattr(source, "service_groups", ()):
        source_groups.setdefault((original.vdom or "root", original.name), []).append(original)
    for item in result.services:
        supported = item.protocol in {"tcp", "udp"} and item.port is not None
        warnings = () if supported else (f"unsupported service protocol or port: {item.protocol}",)
        source_name = item.source_name or item.name
        extra = _source_service_warnings(source_services.get((item.vdom or "root", source_name), ()))
        warnings += extra
        supported = supported and not extra
        services.append(PlannedService(
            source_vdom=item.vdom, source_kind="service", source_object_type="service",
            source_name=item.name,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else getattr(item, "vsys", None), target_name=getattr(options, "service_names", {}).get(item.vdom, {}).get(item.name, item.name),
            status=PANMigrationStatus.SUPPORTED if supported else PANMigrationStatus.UNSUPPORTED,
            warnings=warnings, protocol=item.protocol, destination_port=item.port,
            source_port=item.source_port,
            description=item.comment,
        ))
    explicit_names = {(item.vdom, item.name) for item in (*result.services, *result.groups)}
    references = {(policy.vdom, name) for policy in getattr(source, "policies", ()) for name in policy.service or ()}
    references.update((group.vdom, name) for group in result.groups for name in group.members or ())
    for vdom, name in sorted(references):
        if (vdom, name) in explicit_names or name not in {"HTTP", "DNS"}:
            continue
        vsys = getattr(getattr(options, "vdoms", {}).get(vdom), "vsys", None) if options else None
        if name == "HTTP":
            services.append(PlannedService(source_vdom=vdom, source_kind="predefined_service",
                source_object_type="service", source_name=name, target_vsys=vsys, target_name=getattr(options, "service_names", {}).get(vdom, {}).get(name, name),
                status=PANMigrationStatus.SUPPORTED, protocol="tcp", destination_port="80"))
        else:
            for protocol in ("tcp", "udp"):
                target = f"FG-DNS-{protocol.upper()}"
                services.append(PlannedService(source_vdom=vdom, source_kind="predefined_service",
                    source_object_type="service", source_name=target, target_vsys=vsys, target_name=getattr(options, "service_names", {}).get(vdom, {}).get(target, target),
                    status=PANMigrationStatus.SUPPORTED if (vdom, target) not in explicit_names else PANMigrationStatus.MANUAL_REVIEW,
                    warnings=() if (vdom, target) not in explicit_names else ("generated DNS service name conflicts with source",),
                    protocol=protocol, destination_port="53"))
    groups = tuple(PlannedServiceGroup(
        source_vdom=item.vdom, source_kind="service_group", source_object_type="service_group",
        source_name=item.name,
        status=PANMigrationStatus.MANUAL_REVIEW if item.members is None or any(
            name in {"PING", "ALL"} and (item.vdom, name) not in explicit_names for name in item.members or ()
        ) else PANMigrationStatus.SUPPORTED,
        warnings=("service-group membership is not explicit in the source",) if item.members is None else
            ("service group contains a built-in that cannot be represented as a PAN service member",) if any(
                name in {"PING", "ALL"} and (item.vdom, name) not in explicit_names for name in item.members or ()
            ) else (),
        target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else getattr(item, "vsys", None), target_name=item.name,
        members=tuple(service_target(name, {n for v, n in explicit_names if v == item.vdom}, getattr(options, "service_names", {}).get(item.vdom, {})) for name in item.members or ()),
    ) for item in result.groups)
    checked_groups = []
    for group, normalized in zip(groups, result.groups):
        if normalized.generated:
            extra = _source_service_warnings(source_services.get((group.source_vdom or "root", group.source_name), ()))
        else:
            extra = _source_service_warnings(source_groups.get((group.source_vdom or "root", group.source_name), ()))
            originals = source_groups.get((group.source_vdom or "root", group.source_name), ())
            if len(originals) == 1 and originals[0].comment is not None:
                extra += ('service-group comment has no verified PAN-OS description path; manual metadata review required',)
        checked_groups.append(replace(group, status=PANMigrationStatus.UNSUPPORTED,
                                      warnings=tuple(dict.fromkeys((*group.warnings, *extra)))) if extra else group)
    groups = tuple(checked_groups)
    for vdom, name in sorted(references):
        if name == "DNS" and (vdom, name) not in explicit_names:
            groups += (PlannedServiceGroup(source_vdom=vdom, source_kind="predefined_service",
                source_object_type="service_group", source_name=name,
                target_vsys=getattr(getattr(options, "vdoms", {}).get(vdom), "vsys", None) if options else None,
                target_name=name, status=PANMigrationStatus.SUPPORTED,
                members=tuple(getattr(options, "service_names", {}).get(vdom, {}).get(n, n) for n in ("FG-DNS-TCP", "FG-DNS-UDP"))),)
    for vip in getattr(source, 'vips', ()):
        ports = vip_port_translation(vip, derived)
        if ports is None:
            continue
        vdom = vip.vdom or 'root'
        name = vip_service_name(vip, derived)
        collision = (vdom, name) in explicit_names or any(item.source_vdom == vdom and item.source_name == name for item in services)
        services.append(PlannedService(source_vdom=vdom, source_kind='vip_service', source_object_type='service',
            source_name=name, target_name=getattr(options, 'service_names', {}).get(vdom, {}).get(name, name),
            target_vsys=getattr(getattr(options, 'vdoms', {}).get(vdom), 'vsys', None), protocol=ports[0], destination_port=ports[1],
            status=PANMigrationStatus.MANUAL_REVIEW if collision else PANMigrationStatus.SUPPORTED,
            warnings=('Generated VIP service conflicts with an existing source service',) if collision else ()))
    return tuple(services), groups
