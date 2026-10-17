"""Directional PAN-OS to FortiOS planner."""
from dataclasses import replace

from .models import FGMigrationPlan, FGPlannedItem
from .options import FGMigrationOptions
from .planning.context import PlanningContext
from .planning.source_scope import select_source_scope
from .planning.objects import plan_addresses, plan_services, plan_schedules
from .planning.topology import plan_interfaces, plan_zones, plan_routes
from .planning.policies import plan_policies
from .planning.nat import plan_nat
from .recommendations.support_guidance import manual_inventory
from .target.profile import profile_findings


class PaloAltoToFortiGatePlanner:
    source_vendor = "palo_alto"
    target_vendor = "fortigate"

    def plan(self, source, derived, options=None, **kwargs):
        if not isinstance(options, FGMigrationOptions):
            options = FGMigrationOptions(**(options or {}))
        scope, scope_findings = select_source_scope(source, options)
        findings = scope_findings + profile_findings(options)
        if scope is None:
            return FGMigrationPlan(tuple(manual_inventory(source, ())), findings)
        ctx = PlanningContext(source, derived, options, scope)
        interfaces = plan_interfaces(ctx)
        items = [*plan_addresses(ctx), *plan_services(ctx), *plan_schedules(ctx), *interfaces, *plan_zones(ctx, interfaces), *plan_routes(ctx, interfaces)]
        nat = plan_nat(ctx)
        policies = plan_policies(ctx)
        dnat_hosts = [item for item in nat if item.family == "dnat_address"]
        if len(dnat_hosts) == 1 and len(policies) == 1:
            settings = dict(policies[0].settings)
            settings.update({"dstaddr": (dnat_hosts[0].target_name,), "match-vip-only": ("enable",)})
            policies = [replace(policies[0], settings=tuple(settings.items()))]
        if nat:
            # Unknown NAT overlap blocks every affected traffic rule until a verified independent slice exists.
            nat_dependencies = tuple(i.key for i in nat)
            policies = [replace(item, dependencies=(*item.dependencies, *nat_dependencies)) for item in policies]
        items.extend((*nat, *policies))
        if policies:
            items.append(FGPlannedItem("default-behavior:" + options.source_scope, "manual", options.source_scope,
                "Default security and intrazone behavior", "", "default_behavior", options.vdom, "",
                reasons=("Default security and intrazone equivalence remains manual; generated zones explicitly deny intrazone traffic.",), disposition="BLOCK"))
        items.extend(manual_inventory(source, items))
        if source.extraction_issues or source.unknown_paths or derived.relationship_issues:
            findings += ("Source extraction or topology is incomplete; correct the source before executable conversion.",)
        return FGMigrationPlan(tuple(items), findings)
