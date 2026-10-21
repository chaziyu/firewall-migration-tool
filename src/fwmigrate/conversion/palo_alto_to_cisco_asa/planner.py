"""Independent native PAN-OS to ASA planner. No intermediate vendor model."""

from dataclasses import replace

from .models import ASAMigrationPlan, ASAPlanItem
from .options import ASAMigrationOptions
from .plan_dependencies import TRAFFIC, validate_plan
from .planning.acl import defaults_proven, plan_policies
from .planning.nat import plan_nat
from .planning.objects import plan_addresses, plan_services
from .planning.source_scope import identity, select_source_scope
from .planning.topology import plan_topology


class PaloAltoToCiscoASAPlanner:
    source_vendor = "palo_alto"
    target_vendor = "cisco_asa"

    def plan(self, source, derived, options=None, **kwargs):
        if kwargs:
            raise TypeError("Unsupported PAN-OS to ASA planner arguments")
        options = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**(options or {}))
        selected, issue = select_source_scope(source, options.source_scope)
        if selected is None:
            return ASAMigrationPlan(options.source_scope, options.target_context, options.target_version, (), (issue,))
        objects = [*plan_addresses(source, selected), *plan_services(source, selected)]
        topology, interfaces, memberships, routes, complete = plan_topology(source, selected, options)
        nat, nat_blocked = plan_nat(source, selected)
        policies = plan_policies(source, selected, options, objects, interfaces, memberships, routes, complete, nat_blocked, derived)
        reasons = []
        if not options.new_target_confirmed:
            reasons.append("NEW_EMPTY_ROUTED_SINGLE_TARGET_REQUIRES_EXPLICIT_CONFIRMATION")
        if not complete:
            reasons.append("COMPLETE_CONNECTED_STATIC_ROUTING_PROOF_REQUIRED")
        if not defaults_proven(source, selected):
            reasons.append("EXPLICIT_UNLOGGED_DROP_DEFAULT_RULES_REQUIRED")
        if nat_blocked:
            reasons.append("ACTIVE_OR_UNKNOWN_NAT_BLOCKS_TRAFFIC_UNIT")
        inactive_paths = [row.source_path for row in source.nat_rules if row.disabled == "yes"]
        if any(row.unsupported and not any(row.source_path.startswith(path) for path in inactive_paths)
               for row in source.source_inventory):
            reasons.append("UNSUPPORTED_SOURCE_EVIDENCE_BLOCKS_TRAFFIC_PROOF")
        controls = []
        if options.permit_inter_interface:
            controls.append("same-security-traffic permit inter-interface")
        if options.permit_intra_interface:
            controls.append("same-security-traffic permit intra-interface")
        scope = options.source_scope
        security = ASAPlanItem("security-controls:" + scope, "security_controls", scope, "design", "ASA security controls", "", "security-controls",
                               (("commands", tuple(controls)),), blockers=tuple(reasons))
        traffic = [*topology, *policies, security]
        for name, interface in interfaces.items():
            nameif = dict(interface.settings).get("nameif")
            dependencies = tuple(row.key for row in policies if row.family == "policy")
            default_key = "default:" + interface.key
            traffic.append(ASAPlanItem(default_key, "default_behavior", scope, "default", name, "", f"default-{name}",
                                       (("commands", (f"access-list PAN_{nameif} extended deny ip any4 any4",)),), dependencies,
                                       tuple(reasons), 1000000))
            traffic.append(ASAPlanItem("binding:" + interface.key, "acl_binding", scope, "binding", name, "", f"binding-{name}",
                                       (("commands", (f"access-group PAN_{nameif} in interface {nameif}",)),),
                                       (default_key, interface.key, security.key), tuple(reasons), 1000001))
        bindings = tuple(row.key for row in traffic if row.family == "acl_binding")
        for name, interface in interfaces.items():
            physical = dict(interface.settings).get("interface")
            traffic.append(ASAPlanItem("activation:" + interface.key, "activation", scope, "design", name, "", f"activate-{name}",
                                       (("commands", (f"interface {physical}", " no shutdown", "exit")),), bindings,
                                       tuple(reasons), 1000002))
        all_items = [*objects, *nat, *traffic]
        # Preserve every unsupported source record as manual coverage; incomplete extraction blocks creation.
        represented = {row.source_path for row in all_items}
        for record in source.source_inventory:
            if record.source_path not in represented and record.unsupported:
                all_items.append(ASAPlanItem(identity(record, "manual"), "manual", scope, record.kind,
                                             record.name or "(unnamed)", record.source_path, "manual-" + str(record.source_order),
                                             blockers=("SOURCE_RECORD_REQUIRES_MANUAL_IMPLEMENTATION",)))
        if source.unknown_paths or source.extraction_issues:
            all_items = [replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_EXTRACTION_INCOMPLETE")))) for row in all_items]
        all_items = [replace(row, approval_group="traffic") if row.family in TRAFFIC else row for row in all_items]
        plan = ASAMigrationPlan(scope, options.target_context, options.target_version, tuple(all_items),
                                ("Offline export. Physical ports, capacity and live acceptance remain unverified.",))
        return validate_plan(plan)
