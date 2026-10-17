"""Pair-specific FortiGate to Juniper SRX planner."""

from .models import SRXFinding, SRXMigrationPlan
from .options import SRXMigrationOptions
from .planning.nat import attach_nat_review_groups, plan_nat
from .planning.objects import plan_objects
from .planning.policies import plan_policies
from .planning.schedules import plan_schedules
from .planning.topology import _global_blockers, plan_topology
from .requirements import build_mapping_requirements, source_vdoms


class FortiGateToJuniperSRXPlanner:
    source_vendor = "fortigate"
    target_vendor = "juniper_srx"

    def plan(self, source, derived, options=None, *, source_inventory=None, **kwargs) -> SRXMigrationPlan:
        if kwargs:
            raise TypeError(f"Unsupported SRX planner arguments: {', '.join(sorted(kwargs))}")
        if options is None:
            options = SRXMigrationOptions()
        elif isinstance(options, dict):
            options = SRXMigrationOptions(**options)
        elif not isinstance(options, SRXMigrationOptions):
            raise TypeError("options must be SRXMigrationOptions, a mapping, or null")

        vdoms = source_vdoms(source)
        decisions = build_mapping_requirements(source, derived, options)
        findings = []
        if options.source_vdom is None:
            findings.append(SRXFinding(
                "SOURCE_VDOM_REQUIRED", "Choose one FortiGate VDOM explicitly.",
                source_kind="source", source_name="FortiGate",
            ))
        elif options.source_vdom not in vdoms:
            findings.append(SRXFinding(
                "SOURCE_VDOM_UNAVAILABLE", "The selected FortiGate VDOM is not present in the extracted source.",
                source_vdom=options.source_vdom, source_kind="source", source_name="FortiGate",
            ))
        for vdom in vdoms:
            if vdom != options.source_vdom:
                findings.append(SRXFinding(
                    "OTHER_VDOM_REMAINS_MANUAL",
                    f"FortiGate VDOM {vdom!r} is outside this one-VDOM SRX plan and remains manual.",
                    source_vdom=vdom, source_kind="source", source_name="FortiGate", blocking=False,
                ))
        findings.extend(
            SRXFinding(code, code.replace("_", " ").capitalize(), options.source_vdom,
                       "target", "Juniper SRX")
            for code in _global_blockers(options)
        )

        if options.source_vdom not in vdoms:
            return SRXMigrationPlan(
                options.source_vdom, options.target_context, options.target_version,
                options.target_mode, options.routing_table, (), decisions, tuple(findings),
            )
        items = [
            *plan_objects(source, derived, options.source_vdom),
            *plan_topology(source, derived, options, options.source_vdom),
        ]
        schedules = plan_schedules(source, options, options.source_vdom)
        policies, policy_findings = plan_policies(
            source, derived, options, options.source_vdom, items, schedules, source_inventory,
        )
        nat_items, nat_links, nat_policy_blockers, nat_findings = plan_nat(
            source, derived, options.source_vdom, policies, source_inventory,
        )
        policies = attach_nat_review_groups(policies, nat_links, nat_policy_blockers)
        items.extend((*schedules, *nat_items, *policies))
        findings.extend(policy_findings)
        findings.extend(nat_findings)
        findings.append(SRXFinding(
            "DEFAULT_AND_INTRAZONE_BEHAVIOR_REQUIRES_REVIEW",
            "Review target default behavior and source intrazone handling separately.",
            options.source_vdom, "policy", "FortiGate",
            blocking=False,
        ))
        return SRXMigrationPlan(
            options.source_vdom, options.target_context, options.target_version,
            options.target_mode, options.routing_table, tuple(items), decisions, tuple(findings),
        )
