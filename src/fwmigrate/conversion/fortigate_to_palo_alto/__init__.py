"""FortiGate to Palo Alto migration-planning boundary."""

from .models import (
    MigrationIssue,
    MigrationSourceRef,
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedAddress,
    PlannedAddressGroup,
    PlannedNATRule,
    PlannedPANItem,
    PlannedSchedule,
    PlannedSecurityRule,
    PlannedService,
    PlannedServiceGroup,
    PlannedStaticRoute,
    PlannedZone,
)
from .options import InterfaceMapping, PANMigrationOptions, VDOMMapping
from .planner import FortiGateToPaloAltoPlanner

__all__ = [
    "FortiGateToPaloAltoPlanner",
    "InterfaceMapping",
    "MigrationIssue",
    "MigrationSourceRef",
    "PANMigrationOptions",
    "PANMigrationPlan",
    "PANMigrationStatus",
    "PlannedAddress",
    "PlannedAddressGroup",
    "PlannedNATRule",
    "PlannedPANItem",
    "PlannedSchedule",
    "PlannedSecurityRule",
    "PlannedService",
    "PlannedServiceGroup",
    "PlannedStaticRoute",
    "PlannedZone",
    "VDOMMapping",
]
