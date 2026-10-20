"""Build a pair-specific Management/Gaia Check Point plan."""

from .models import CPFinding, CPMigrationPlan
from .design.proposals import propose_new_target
from .options import CPMigrationOptions
from .planning.access_policy import plan_access_rules
from .planning.gaia import plan_gaia_routes
from .planning.naming import item_key
from .planning.objects import plan_addresses, plan_ipv6_addresses, plan_services
from .planning.package import plan_new_package
from .requirements import build_mapping_requirements, source_vdoms


class FortiGateToCheckPointPlanner:
    source_vendor = "fortigate"
    target_vendor = "checkpoint"

    def plan(self, source, derived, options, *, source_inventory=()):
        if not isinstance(options, CPMigrationOptions):
            options = CPMigrationOptions(**options)
        options = propose_new_target(source, options)
        vdom = options.source_vdom
        findings = []
        items = []
        known_vdoms = source_vdoms(source)
        if not vdom:
            findings.append(CPFinding("SOURCE_VDOM_REQUIRED", "Select one explicit FortiGate VDOM before planning.", blocking=True))
            return CPMigrationPlan(None, options.to_dict(), (), build_mapping_requirements(source, options), tuple(findings))
        if vdom not in known_vdoms:
            findings.append(CPFinding("SOURCE_VDOM_UNKNOWN", "The selected FortiGate VDOM is not present in the source.", vdom, blocking=True))
            return CPMigrationPlan(vdom, options.to_dict(), (), build_mapping_requirements(source, options), tuple(findings))
        if any(value != vdom for value in known_vdoms):
            findings.append(CPFinding("OTHER_SOURCE_VDOMS_REMAIN_MANUAL", "Only the selected VDOM is planned; other FortiGate VDOMs remain manual work.", vdom, "source", "FortiGate", False))

        context_blockers = []
        if options.target_mode == "existing" and not options.management_target:
            context_blockers.append("CHECKPOINT_MANAGEMENT_TARGET_REQUIRED")
        if options.target_mode == "existing" and not options.management_domain:
            context_blockers.append("CHECKPOINT_MANAGEMENT_DOMAIN_REQUIRED")
        if options.management_api_version != "1.8.1":
            context_blockers.append("CHECKPOINT_MANAGEMENT_API_VERSION_MUST_BE_1_8_1")

        address_items, address_names = plan_addresses(source, derived, vdom, context_blockers)
        service_items, service_names, normalized_service_names = plan_services(source, derived, vdom, context_blockers)
        items.extend(address_items)
        items.extend(plan_ipv6_addresses(source, derived, vdom, context_blockers))
        items.extend(service_items)
        if options.target_mode == "new":
            items.extend(plan_new_package(vdom, options, context_blockers))
        policy_items, central_snat = plan_access_rules(
            source, derived, vdom, options, address_names, service_names,
            normalized_service_names, source_inventory,
        )
        items.extend(policy_items)
        items.extend(plan_gaia_routes(source, vdom, options))

        for group in source.address_groups:
            if (group.vdom or "root") == vdom:
                findings.append(CPFinding("ADDRESS_GROUP_EXPANDED_IN_RULES", "Static address groups are expanded into Check Point rule object lists; no Check Point group object is created.", vdom, "address_group", group.name, False))
        for group in source.service_groups:
            if (group.vdom or "root") == vdom:
                findings.append(CPFinding("SERVICE_GROUP_EXPANDED_IN_RULES", "Static service groups are expanded into Check Point rule service lists; no Check Point service-group object is created.", vdom, "service_group", group.name, False))
        if central_snat:
            findings.append(CPFinding("UNREPRESENTED_CENTRAL_SNAT", "FortiGate central SNAT source evidence is present and blocks dependent access-rule requests.", vdom, "nat", "central-snat-map", False))
        if any(row.family == "static_route" and row.blockers for row in items):
            findings.append(CPFinding("GAIA_STATIC_ROUTE_COVERAGE_PARTIAL", "Unsupported, incomplete, multipath, or targetless Gaia route rows remain manual.", vdom, "route", None, False))
        if any(row.family == "policy" and row.blockers for row in items):
            findings.append(CPFinding("ACCESS_POLICY_COVERAGE_PARTIAL", "Unsupported or incomplete FortiGate policies remain manual; later policy rows are blocked when an earlier row is not representable.", vdom, "policy", None, False))
        findings.append(CPFinding("DESTINATION_NOT_COMPARED", "This Check Point export is not compared with a destination snapshot; validate domain names, object-name conflicts, package/layer contents, and cleanup placement before applying requests.", vdom, "target", "Check Point", False))
        findings.append(CPFinding("MANAGEMENT_GAIA_ACTIVATION_MANUAL", "Management API requests and Gaia commands are separate offline files. Authentication, publishing, policy installation, and save config are excluded.", vdom, "target", "Check Point", False))
        if options.target_mode == "new":
            findings = [row for row in findings if row.code != "DESTINATION_NOT_COMPARED"]
            findings.append(CPFinding("NEW_TARGET_PROPOSAL", "Create a new package and Drop cleanup rule. No destination snapshot is required. Select the correct Management Domain when logging in and the gateway before policy installation; proposed names must be unused. Gaia addressing and topology require separate setup.", vdom, "target", "Check Point", False))
        return CPMigrationPlan(vdom, options.to_dict(), tuple(items), build_mapping_requirements(source, options), tuple(findings))

