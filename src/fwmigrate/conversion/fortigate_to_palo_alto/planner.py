"""FortiGate to Palo Alto migration planner."""

from typing import Any

from ..contracts import VendorDerivedViews, VendorSourceConfig
from .addresses import plan_addresses
from .nat import plan_nat
from .policies import plan_policies
from .routing import plan_routes
from .schedules import plan_schedules
from .services import plan_services
from .topology import plan_topology
from .models import PANMigrationPlan
from .options import PANMigrationOptions


class FortiGateToPaloAltoPlanner:
    source_vendor = "fortigate"
    target_vendor = "palo_alto"

    def plan(
        self,
        source: VendorSourceConfig,
        derived: VendorDerivedViews,
        options: PANMigrationOptions | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> PANMigrationPlan:
        """Build the supported portion of a pair-specific migration plan."""
        del kwargs
        if options is None:
            options = PANMigrationOptions()
        elif isinstance(options, dict):
            options = PANMigrationOptions(**options)
        addresses, groups, issues = plan_addresses(source, options)
        services, service_groups = plan_services(derived)
        schedules = plan_schedules(source)
        zones = plan_topology(source, derived, options)
        routes = plan_routes(source, options)
        policies = plan_policies(source, options)
        nat_rules = plan_nat(source, derived, options)
        return PANMigrationPlan(
            addresses=addresses,
            address_groups=groups,
            services=services,
            service_groups=service_groups,
            schedules=schedules,
            zones=zones,
            static_routes=routes,
            security_rules=policies,
            nat_rules=nat_rules,
            issues=issues,
        )
