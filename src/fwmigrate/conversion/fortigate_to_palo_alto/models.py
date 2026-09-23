"""Pair-specific FortiGate to Palo Alto migration-plan models."""

from dataclasses import dataclass, field
from enum import StrEnum


class PANMigrationStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class MigrationSourceRef:
    source_vdom: str | None = None
    source_kind: str | None = None
    source_name: str | None = None
    source_policy_id: int | None = None


@dataclass(frozen=True, slots=True)
class MigrationIssue:
    code: str
    message: str
    status: PANMigrationStatus = PANMigrationStatus.MANUAL_REVIEW
    source: MigrationSourceRef = field(default_factory=MigrationSourceRef)


@dataclass(frozen=True, slots=True)
class PlannedPANItem:
    source_vdom: str | None = None
    source_kind: str | None = None
    source_object_type: str | None = None
    source_name: str | None = None
    source_policy_id: int | None = None
    status: PANMigrationStatus = PANMigrationStatus.MANUAL_REVIEW
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedAddress(PlannedPANItem):
    address_type: str | None = None
    value: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedAddressGroup(PlannedPANItem):
    members: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedService(PlannedPANItem):
    protocol: str | None = None
    destination_port: str | None = None
    source_port: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedServiceGroup(PlannedPANItem):
    members: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedSchedule(PlannedPANItem):
    schedule_type: str | None = None
    value: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedZone(PlannedPANItem):
    interfaces: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedStaticRoute(PlannedPANItem):
    destination: str | None = None
    gateway: str | None = None
    interface: str | None = None
    virtual_router: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedSecurityRule(PlannedPANItem):
    from_zones: tuple[str, ...] = ()
    to_zones: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    schedule: str | None = None
    action: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedNATRule(PlannedPANItem):
    source_translation: str | None = None
    destination_translation: str | None = None
    from_zones: tuple[str, ...] = ()
    to_zones: tuple[str, ...] = ()
    source_addresses: tuple[str, ...] = ()
    destination_addresses: tuple[str, ...] = ()
    services: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PANMigrationPlan:
    addresses: tuple[PlannedAddress, ...] = ()
    address_groups: tuple[PlannedAddressGroup, ...] = ()
    services: tuple[PlannedService, ...] = ()
    service_groups: tuple[PlannedServiceGroup, ...] = ()
    schedules: tuple[PlannedSchedule, ...] = ()
    zones: tuple[PlannedZone, ...] = ()
    static_routes: tuple[PlannedStaticRoute, ...] = ()
    security_rules: tuple[PlannedSecurityRule, ...] = ()
    nat_rules: tuple[PlannedNATRule, ...] = ()
    issues: tuple[MigrationIssue, ...] = field(default_factory=tuple)
