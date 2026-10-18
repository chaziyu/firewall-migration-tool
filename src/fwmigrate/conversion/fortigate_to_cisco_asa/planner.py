"""Build the supported FortiGate to single-context routed ASA plan."""

from .models import ASAFinding, ASAMigrationPlan
from .options import ASAMigrationOptions
from .requirements import build_mapping_requirements, source_vdoms
from .planning.naming import item_key
from .planning.objects import plan_objects
from .planning.topology import plan_topology
from .planning.schedules import plan_schedules
from .planning.acl import plan_policies
from .planning.nat import plan_nat
from dataclasses import replace


class FortiGateToCiscoASAPlanner:
    source_vendor = "fortigate"
    target_vendor = "cisco_asa"

    def plan(self, source, derived, options=None, *, target_evidence=None, source_inventory=()):
        if options is None:
            options = ASAMigrationOptions()
        elif isinstance(options, dict):
            options = ASAMigrationOptions(**options)
        elif not isinstance(options, ASAMigrationOptions):
            raise TypeError("options must be ASAMigrationOptions, a mapping, or null")
        vdoms = source_vdoms(source)
        findings = []
        if options.source_vdom is None:
            findings.append(ASAFinding("SOURCE_VDOM_REQUIRED", "Choose one FortiGate VDOM explicitly.", source_kind="source", source_name="FortiGate"))
        elif options.source_vdom not in vdoms:
            findings.append(ASAFinding("SOURCE_VDOM_UNAVAILABLE", "The selected FortiGate VDOM is not present in the extracted source.", options.source_vdom, "source", "FortiGate"))
        for vdom in vdoms:
            if vdom != options.source_vdom:
                findings.append(ASAFinding("OTHER_VDOM_REMAINS_MANUAL", f"FortiGate VDOM {vdom!r} is outside this one-VDOM ASA plan and remains manual.", vdom, "source", "FortiGate", False))
        for field, expected in (("target_context", "single"), ("target_version", "9.20"), ("target_mode", "routed")):
            if getattr(options, field) != expected:
                findings.append(ASAFinding("ASA_TARGET_PROFILE_MISMATCH", f"This export supports only {field}={expected!r}.", options.source_vdom, "target", "Cisco ASA"))
        if options.source_vdom not in vdoms:
            return ASAMigrationPlan(options.source_vdom, options.target_context, options.target_version,
                                    options.target_mode, (), build_mapping_requirements(source, options), tuple(findings))

        items, _ = plan_topology(source, options)
        object_items, address_names, service_names = plan_objects(source, derived, options.source_vdom)
        schedule_items = plan_schedules(source, options)
        nat_items = plan_nat(source, derived, options, address_names, target_evidence)
        target = target_evidence
        policy_items = plan_policies(source, derived, options, address_names, service_names,
                                     target_evidence=target, source_inventory=source_inventory)
        items.extend((*object_items, *schedule_items, *nat_items, *policy_items))
        fixed_nat = next((item for item in nat_items if item.family == "nat" and item.approval_group), None)
        if fixed_nat:
            policy_key = item_key(options.source_vdom, "policy", fixed_nat.source_name)
            related = {policy_key, *(item.key for item in policy_items
                        if item.family == "acl_binding")}
            items = [replace(item, approval_group=fixed_nat.approval_group) if item.key in related else item for item in items]
        for policy in source.policies:
            if (policy.vdom or "root") == options.source_vdom and policy.policy_id is None:
                findings.append(ASAFinding("SOURCE_POLICY_ORDER_UNAVAILABLE", "A policy has no explicit ordering identity; affected traffic remains manual.", options.source_vdom, "policy", policy.name or "unknown"))
        if source.security_policies or source.sdwans:
            findings.append(ASAFinding("ADDITIONAL_SOURCE_FEATURES_REMAIN_MANUAL", "Security policies and SD-WAN rules are not part of this ASA conversion subset.", options.source_vdom, "source", "FortiGate", False))
        return ASAMigrationPlan(options.source_vdom, options.target_context, options.target_version,
                                options.target_mode, tuple(items), build_mapping_requirements(source, options), tuple(findings))
