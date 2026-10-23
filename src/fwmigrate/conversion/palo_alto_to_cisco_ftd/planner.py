"""Independent PAN-OS to Cisco FMC / FTD planning."""

from dataclasses import replace

from .design.proposals import propose_new_target
from .models import FTDFinding, FTDMigrationPlan
from .options import FTDMigrationOptions
from .plan_dependencies import validate_plan
from .planning.access_policy import defaults_proven, plan_access_rules
from .planning.acp import plan_new_acp
from .planning.objects import item, plan_addresses, plan_services, plan_zones
from .planning.source_scope import in_scope, select_source_scope
from .requirements import build_mapping_requirements


class PaloAltoToCiscoFTDPlanner:
    source_vendor = "palo_alto"
    target_vendor = "cisco_ftd"

    def plan(self, source, derived, options=None, *, source_inventory=()):
        options = propose_new_target(
            source,
            options if isinstance(options, FTDMigrationOptions) else FTDMigrationOptions(**(options or {})),
        )
        selected, issue = select_source_scope(source, options.source_scope)
        decisions = build_mapping_requirements(source, options)
        if selected is None:
            return FTDMigrationPlan(
                options.source_scope,
                options.to_dict(),
                (),
                decisions,
                (FTDFinding("SOURCE_SCOPE_REQUIRED", issue, blocking=True),),
            )

        context = []
        if options.fmc_api_version != "7.7.0":
            context.append("FMC_API_VERSION_MUST_BE_7_7_0")
        if not options.domain_id:
            context.append("EXPLICIT_FMC_DOMAIN_UUID_REQUIRED")
        if not options.manager_target:
            context.append("EXPLICIT_FMC_MANAGER_REQUIRED")
        if options.target_mode == "new" and not options.policy_name:
            context.append("NEW_POLICY_NAME_REQUIRED")

        # Unresolved paths are review-only; context blockers prevent export.
        domain_id = options.domain_id or "UNRESOLVED_DOMAIN_UUID"
        addresses = plan_addresses(source, selected, domain_id)
        services = plan_services(source, selected, domain_id)
        zones = plan_zones(source, selected, domain_id)
        objects = [*addresses, *services, *zones]
        objects = [replace(row, blockers=tuple((*row.blockers, *context))) for row in objects]

        traffic, manual = [], []
        if not defaults_proven(source, selected):
            traffic.append("EXPLICIT_UNLOGGED_DROP_DEFAULTS_REQUIRED")

        for obj in (row for row in source.nat_rules if in_scope(row, selected)):
            inactive = obj.disabled == "yes"
            manual.append(
                item(
                    obj,
                    "inactive_nat" if inactive else "nat",
                    blockers=(
                        "SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED"
                        if inactive
                        else "ACTIVE_OR_UNKNOWN_NAT_UNSUPPORTED",
                    ),
                )
            )
            if not inactive:
                traffic.append("ACTIVE_OR_UNKNOWN_NAT_BLOCKS_POLICY_EQUIVALENCE")

        ignored = [obj.source_path for obj in source.nat_rules if obj.disabled == "yes"]
        if any(
            row.unsupported and not any(row.source_path.startswith(path) for path in ignored)
            for row in source.source_inventory
        ):
            traffic.append("UNSUPPORTED_SOURCE_EVIDENCE_BLOCKS_POLICY_PROOF")

        acp_items = (
            plan_new_acp(options.source_scope, options, domain_id, context)
            if options.target_mode == "new"
            else []
        )
        policies = plan_access_rules(
            source, derived, selected, options, domain_id, objects, (*context, *traffic)
        )

        for obj in source.interfaces:
            manual.append(
                item(obj, "interface", blockers=("FTD_DEVICE_INTERFACE_TOPOLOGY_AND_ASSIGNMENT_REQUIRED",))
            )
        for router in source.virtual_routers:
            for obj in router.static_routes:
                manual.append(
                    item(obj, "static_route", blockers=("FTD_ROUTING_AND_EVIDENCE_REQUIRED",))
                )

        rows = [*objects, *acp_items, *policies, *manual]
        findings = [
            FTDFinding(
                "OFFLINE_FMC_SPEC_ONLY",
                "FMC REST requests are exported for offline execution. Interface assignment and deployment remain manual.",
                blocking=False,
            )
        ]
        if source.unknown_paths or source.extraction_issues:
            rows = [replace(row, blockers=(*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE")) for row in rows]
            findings.append(
                FTDFinding("SOURCE_EXTRACTION_INCOMPLETE", "Resolve incomplete source extraction before approval.")
            )
        if options.target_mode == "existing":
            findings.append(
                FTDFinding(
                    "EXISTING_TARGET_INSERTION_UNSUPPORTED",
                    "Existing snapshots support exact object comparison; existing policy placement remains blocked.",
                    blocking=False,
                )
            )

        return validate_plan(
            FTDMigrationPlan(
                options.source_scope,
                options.to_dict(),
                tuple(rows),
                decisions,
                tuple(findings),
            )
        )
