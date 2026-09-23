"""FortiGate service planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedService, PlannedServiceGroup


def plan_services(derived: Any):
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
            status=PANMigrationStatus.SUPPORTED if supported else PANMigrationStatus.UNSUPPORTED,
            warnings=warnings, protocol=item.protocol, destination_port=item.port,
            source_port=item.source_port,
        ))
    groups = tuple(PlannedServiceGroup(
        source_vdom=item.vdom, source_kind="service_group", source_object_type="service_group",
        source_name=item.name, status=PANMigrationStatus.SUPPORTED,
        members=item.members,
    ) for item in result.groups)
    return tuple(services), groups
