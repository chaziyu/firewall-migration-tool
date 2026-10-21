"""Native PAN-OS to Juniper SRX planner."""

from dataclasses import replace

from .models import SRXMigrationPlan
from .options import SRXMigrationOptions
from .planning.nat import plan_nat
from .planning.objects import plan_addresses, plan_services
from .planning.policies import plan_policies
from .planning.source_scope import select_source_scope
from .planning.topology import plan_interfaces, plan_routes, plan_zones


class PaloAltoToJuniperSRXPlanner:
    source_vendor = "palo_alto"
    target_vendor = "juniper_srx"

    def plan(self, source, derived, options=None, **kwargs):
        if kwargs:
            raise TypeError(f"Unsupported PAN-OS to SRX planner arguments: {', '.join(sorted(kwargs))}")
        if options is None:
            options = SRXMigrationOptions()
        elif isinstance(options, dict):
            options = SRXMigrationOptions(**options)
        elif not isinstance(options, SRXMigrationOptions):
            raise TypeError("options must be SRXMigrationOptions, a mapping, or null")
        selected, issue = select_source_scope(source, options.source_scope)
        scopes = tuple(sorted({scope.name for scope in source.scopes if scope.kind == "vsys"}))
        if selected is None:
            return SRXMigrationPlan(options.source_scope, options.target_context, options.target_version, (),
                                    (issue or "A PAN-OS VSYS source scope is required.",))
        objects = [*plan_addresses(source, selected), *plan_services(source, selected)]
        interfaces, by_source = plan_interfaces(source, selected, options)
        zones, zone_names = plan_zones(source, selected, options, interfaces, by_source)
        routes = plan_routes(source, selected, by_source, options)
        nat_items, nat_blocked = plan_nat(source, selected)
        policies = plan_policies(source, selected, options, objects, zone_names, nat_blocked)
        findings = []
        if len(scopes) > 1:
            findings.append("Other VSYS scopes remain outside this migration plan.")
        if source.extraction_issues or source.unknown_paths:
            findings.append("PAN-OS extraction contains unknown or incomplete source evidence.")
            objects = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE"))))
                       for row in objects]
            interfaces = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE"))))
                          for row in interfaces]
            zones = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE"))))
                     for row in zones]
            routes = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE"))))
                      for row in routes]
            nat_items = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE"))))
                         for row in nat_items]
            policies = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE"))))
                        for row in policies]
        if policies:
            findings.append("PAN-OS default security rules and intrazone behavior require separate review.")
        return SRXMigrationPlan(options.source_scope, options.target_context, options.target_version,
                                tuple((*objects, *interfaces, *zones, *routes, *nat_items, *policies)), tuple(findings))
