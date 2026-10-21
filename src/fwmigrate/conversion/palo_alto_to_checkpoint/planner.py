"""Independent PAN-OS to Check Point Management planning."""

from dataclasses import replace

from .design.proposals import propose_new_target
from .models import CPFinding, CPMigrationPlan
from .options import CPMigrationOptions
from .plan_dependencies import validate_plan
from .planning.access_policy import defaults_proven, plan_access_rules
from .planning.objects import item, plan_addresses, plan_services
from .planning.package import plan_new_package
from .planning.source_scope import in_scope, select_source_scope
from .requirements import build_mapping_requirements


class PaloAltoToCheckPointPlanner:
    source_vendor = "palo_alto"
    target_vendor = "checkpoint"

    def plan(self, source, derived, options=None, *, source_inventory=()):
        options = propose_new_target(source, options if isinstance(options, CPMigrationOptions)
                                     else CPMigrationOptions(**(options or {})))
        selected, issue = select_source_scope(source, options.source_scope)
        decisions = build_mapping_requirements(source, options)
        if selected is None:
            return CPMigrationPlan(options.source_scope, options.to_dict(), (), decisions,
                                   (CPFinding("SOURCE_SCOPE_REQUIRED", issue, blocking=True),))
        context = []
        if options.management_api_version != "1.8.1":
            context.append("MANAGEMENT_API_VERSION_MUST_BE_1_8_1")
        if options.target_mode == "existing" and (not options.management_domain or not options.management_target):
            context.append("EXPLICIT_MANAGEMENT_SERVER_AND_DOMAIN_REQUIRED")
        if options.target_mode == "new" and not options.policy_package:
            context.append("NEW_PACKAGE_NAME_REQUIRED")
        objects = [*plan_addresses(source, selected), *plan_services(source, selected)]
        objects = [replace(row, blockers=tuple((*row.blockers, *context))) for row in objects]
        traffic, manual = [], []
        if not defaults_proven(source, selected):
            traffic.append("EXPLICIT_UNLOGGED_DROP_DEFAULTS_REQUIRED")
        for obj in (row for row in source.nat_rules if in_scope(row, selected)):
            inactive = obj.disabled == "yes"
            manual.append(item(obj, "inactive_nat" if inactive else "nat", blockers=(
                "SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED" if inactive else "ACTIVE_OR_UNKNOWN_NAT_UNSUPPORTED",)))
            if not inactive:
                traffic.append("ACTIVE_OR_UNKNOWN_NAT_BLOCKS_POLICY_EQUIVALENCE")
        ignored = [obj.source_path for obj in source.nat_rules if obj.disabled == "yes"]
        if any(row.unsupported and not any(row.source_path.startswith(path) for path in ignored)
               for row in source.source_inventory):
            traffic.append("UNSUPPORTED_SOURCE_EVIDENCE_BLOCKS_POLICY_PROOF")
        for zone in (row for row in source.zones if in_scope(row, selected)):
            extra = zone.model_dump(exclude={"name", "source_path", "scope", "source_order", "explicit_fields",
                "raw_extra", "network_type", "members", "description", "tags"})
            if zone.raw_extra or zone.network_type != "layer3" or any(extra.values()):
                traffic.append("SOURCE_ZONE_BEHAVIOR_UNPROVEN")
        packages = plan_new_package(options.source_scope, options, context) if options.target_mode == "new" else []
        policies = plan_access_rules(source, derived, selected, options, objects, (*context, *traffic))
        for obj in source.interfaces:
            manual.append(item(obj, "interface", blockers=("GAIA_INTERFACE_TOPOLOGY_AND_EVIDENCE_REQUIRED",)))
        for router in source.virtual_routers:
            for obj in router.static_routes:
                manual.append(item(obj, "static_route", blockers=("GAIA_ROUTING_AND_EVIDENCE_REQUIRED",)))
        rows = [*objects, *packages, *policies, *manual]
        findings = [CPFinding("OFFLINE_MANAGEMENT_ONLY", "Gaia, zone assignment, activation and live acceptance remain manual.", blocking=False)]
        if source.unknown_paths or source.extraction_issues:
            rows = [replace(row, blockers=(*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE")) for row in rows]
            findings.append(CPFinding("SOURCE_EXTRACTION_INCOMPLETE", "Resolve incomplete source extraction before approval."))
        if options.target_mode == "existing":
            findings.append(CPFinding("EXISTING_TARGET_INSERTION_UNSUPPORTED",
                "Existing snapshots support exact object comparison; existing policy placement remains blocked.", blocking=False))
        return validate_plan(CPMigrationPlan(options.source_scope, options.to_dict(), tuple(rows), decisions, tuple(findings)))
