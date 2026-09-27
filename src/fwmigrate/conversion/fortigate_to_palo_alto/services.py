"""FortiGate service planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedService, PlannedServiceGroup


PAN_BUILTIN_SERVICES = frozenset({"any", "service-https"})


def service_target(name, explicit_names):
    if name in explicit_names:
        return name
    return {"ALL": "any", "HTTPS": "service-https"}.get(name, name)


def plan_services(derived: Any, options: Any = None, source: Any = None):
    result = getattr(derived, "services", None)
    if result is None:
        return (), ()
    services = []
    for item in result.services:
        supported = item.protocol in {"tcp", "udp"} and item.port is not None
        warnings = () if supported else (f"unsupported service protocol or port: {item.protocol}",)
        services.append(PlannedService(
            source_vdom=item.vdom, source_kind="service", source_object_type="service",
            source_name=item.name,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else getattr(item, "vsys", None), target_name=item.name,
            status=PANMigrationStatus.SUPPORTED if supported else PANMigrationStatus.UNSUPPORTED,
            warnings=warnings, protocol=item.protocol, destination_port=item.port,
            source_port=item.source_port,
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
                source_object_type="service", source_name=name, target_vsys=vsys, target_name=name,
                status=PANMigrationStatus.SUPPORTED, protocol="tcp", destination_port="80"))
        else:
            for protocol in ("tcp", "udp"):
                target = f"FG-DNS-{protocol.upper()}"
                services.append(PlannedService(source_vdom=vdom, source_kind="predefined_service",
                    source_object_type="service", source_name=target, target_vsys=vsys, target_name=target,
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
        members=tuple(service_target(name, {n for v, n in explicit_names if v == item.vdom}) for name in item.members or ()),
    ) for item in result.groups)
    for vdom, name in sorted(references):
        if name == "DNS" and (vdom, name) not in explicit_names:
            groups += (PlannedServiceGroup(source_vdom=vdom, source_kind="predefined_service",
                source_object_type="service_group", source_name=name,
                target_vsys=getattr(getattr(options, "vdoms", {}).get(vdom), "vsys", None) if options else None,
                target_name=name, status=PANMigrationStatus.SUPPORTED,
                members=("FG-DNS-TCP", "FG-DNS-UDP")),)
    return tuple(services), groups
