"""FortiGate to Palo Alto migration planner."""

from typing import Any

from ..contracts import VendorDerivedViews, VendorSourceConfig
from .planning.addresses import plan_addresses
from .planning.dhcp import plan_dhcp
from .planning.nat import plan_nat
from .planning.interfaces import plan_interfaces
from .planning.policies import plan_policies
from .planning.routing import plan_routes
from .planning.schedules import plan_schedules
from .planning.services import plan_services
from .planning.topology import plan_topology
from .requirements import build_mapping_requirements
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
        include_configuration = kwargs.get("include_configuration", False)
        if options is None:
            options = PANMigrationOptions()
        elif isinstance(options, dict):
            options = PANMigrationOptions(**options)
        addresses, groups, issues = plan_addresses(source, options)
        services, service_groups = plan_services(derived, options, source)
        schedules = plan_schedules(source, options)
        interfaces = plan_interfaces(source, options)
        requirements = build_mapping_requirements(source, derived, include_configuration=include_configuration)
        zones = plan_topology(source, derived, options, requirements["required_zone_keys"],
                              include_configuration=include_configuration)
        routes = plan_routes(source, options, derived)
        dhcp_servers = plan_dhcp(source, options)
        policies = plan_policies(source, options, derived)
        nat_rules = plan_nat(source, derived, options)
        return PANMigrationPlan(
            addresses=addresses,
            address_groups=groups,
            services=services,
            service_groups=service_groups,
            schedules=schedules,
            interfaces=interfaces,
            zones=zones,
            static_routes=routes,
            dhcp_servers=dhcp_servers,
            security_rules=policies,
            nat_rules=nat_rules,
            issues=issues,
        )
