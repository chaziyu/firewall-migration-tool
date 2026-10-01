"""Prepare review-only configuration using the existing pair-specific planner."""
from dataclasses import asdict, replace
import re

from .draft import PANMigrationDraft, PANDraftDecision, design_digest
from .graph import build_decision_graph
from .models import PANDecisionGraph, PANDecisionDependency
from ..decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key
from ..planner import FortiGateToPaloAltoPlanner
from ..target.target_intent import parse_target_intent
from ..target.target_suggestions import discover_target_candidates, _device
from ..target.target_validation import validate_against_target
from ..target.target_object_reuse import classify_target_object_reuse
from ..target.target_plan_validation import assess_target_plan, _items, item_key
from ..plan_dependencies import build_plan_dependency_index
from ..validation import validate_plan
from ..requirements import build_mapping_requirements


def draft_context(source_digest, reference=None, reference_role=None, target_device=None, intent=None):
    role = reference_role or ("DESTINATION" if reference else None)
    if role not in {None, "DESTINATION", "TEMPLATE"}:
        raise ValueError("reference_role must be DESTINATION, TEMPLATE, or null")
    return {"source_digest": source_digest, "reference_digest": (reference or {}).get("config_digest"),
            "reference_role": role, "target_device": target_device,
            "intent": parse_target_intent(intent), "schema_version": 1}


def _intent_values(context, decisions):
    result = {}
    intent = context["intent"]
    for decision in decisions.decisions:
        if decision.source_kind == "vdom":
            value = intent["vdoms"].get(decision.source_vdom, {}).get(decision.target_field)
        else:
            family = "interfaces" if decision.source_kind == "interface" else "zones"
            field = "interface" if decision.target_field == "target_interface" else "zone"
            mapping = intent[family].get(f"{decision.source_vdom}/{decision.source_name}")
            if mapping is None and len({item.source_vdom for item in decisions.decisions
                    if item.source_kind == decision.source_kind and item.source_name == decision.source_name}) == 1:
                mapping = intent[family].get(decision.source_name)
            value = (mapping or {}).get(field)
        if value:
            result[decision.key] = value
    return result


def build_deterministic_draft(config, derived, decisions, *, source_digest, target=None,
                              target_device=None, reference=None, reference_role=None,
                              intent=None, overrides=None):
    context = draft_context(source_digest, reference, reference_role, target_device, intent)
    overrides = overrides or {}
    by_key = {item.key: item for item in decisions.decisions}
    if not isinstance(overrides, dict) or set(overrides) - set(by_key):
        raise ValueError("draft_overrides must select current decision keys")
    if any(not isinstance(value, str) or not value.strip() for value in overrides.values()):
        raise ValueError("draft overrides must be non-empty strings")
    context["overrides"] = {key: value.strip() for key, value in overrides.items()}
    graph = build_decision_graph(config, derived, decisions,
                                build_mapping_requirements(config, derived, include_configuration=True))
    dependencies = {row.decision_key: set(row.depends_on) for row in graph.dependencies}
    for item in decisions.decisions:
        if item.source_kind != "vdom":
            vsys_key = make_decision_key(item.source_vdom, "vdom", item.source_vdom, "vsys")
            if vsys_key in by_key:
                dependencies[item.key].add(vsys_key)
    interfaces = {(item.vdom or "root", item.name): item for item in config.interfaces}
    zone_parents = {}
    for item in decisions.decisions:
        if item.source_kind == "interface" and item.target_field == "target_zone":
            memberships = [zone for zone in config.zones if (zone.vdom or "root") == item.source_vdom
                           and item.source_name in (zone.members or ())]
            if len(memberships) == 1:
                parent = make_decision_key(item.source_vdom, "zone", memberships[0].name, "target_zone")
                if parent in by_key:
                    dependencies[item.key].add(parent)
                    zone_parents[item.key] = parent
        if item.target_field == "virtual_router":
            parent = make_decision_key(item.source_vdom, "vdom", item.source_vdom, "vsys")
            if parent in by_key:
                dependencies[item.key].add(parent)
    graph = PANDecisionGraph(tuple(PANDecisionDependency(key, tuple(sorted(parents)))
                                  for key, parents in sorted(dependencies.items())))
    values = _intent_values(context, decisions)
    values.update(context["overrides"])
    explicit = set(values)
    approved = {item.key for item in decisions.decisions if item.value and
                (item.review_state is PANDecisionReviewState.CONFIRMED or item.mode is PANDecisionMode.AUTO)}
    values.update({key: by_key[key].value for key in approved if key not in explicit})
    destination = target if context["reference_role"] == "DESTINATION" and target_device else None
    evidence = {key: ["Explicit engineer allocation" if key in explicit else "Existing engineer decision"] for key in values}
    # Draft parents unlock evidence discovery; authoritative decisions never change.
    for _ in range(len(by_key) + 1):
        previous = dict(values)
        candidates = discover_target_candidates(config, decisions, target, target_device,
                        draft_values=values) if target is not None and target_device else {}
        for key in graph.topological_order():
            item = by_key[key]
            if key in zone_parents and key not in explicit and key not in approved and values.get(zone_parents[key]):
                values[key] = values[zone_parents[key]]
                evidence[key] = ["Derived from the proposed mapping of the explicit source zone"]
            if key in values or item.mode is PANDecisionMode.UNSUPPORTED:
                continue
            options = candidates.get(key, ())
            compatible = [row for row in options if row.get("class") == "STRONG"
                          and row.get("available", True) and not row.get("contested")]
            if destination is None and item.target_field == "target_interface":
                compatible = []
            if item.target_field == "vsys":
                # Never silently merge multiple VDOMs into a single destination VSYS.
                compatible = list(options) if len({row.source_vdom for row in decisions.decisions}) == 1 else compatible
            if item.target_field == "virtual_router":
                compatible = [row for row in options if row.get("class") == "STRONG"]
            if len(compatible) == 1:
                values[key] = compatible[0]["value"]
                evidence[key] = list(compatible[0].get("strong_evidence", ())) or ["Unique reference scope"]
                continue
            if item.target_field == "virtual_router":
                values[key] = "vr-" + item.source_vdom
                evidence[key] = ["Source-derived virtual-router name"]
            elif item.target_field == "target_zone":
                values[key] = item.suggested_value if item.evidence_source in {"SOURCE", "DERIVED"} else None
                if not values[key]:
                    values[key] = item.source_name if item.source_kind == "zone" else f"{item.source_vdom}-{item.source_name}"
                evidence[key] = ["Explicit source zone" if item.source_kind == "zone" or item.suggested_value
                                 else "Proposed target zone; no source zone membership inferred"]
            elif item.target_field == "target_interface":
                source = interfaces.get((item.source_vdom, item.source_name))
                parent = values.get(make_decision_key(item.source_vdom, "interface", source.interface, "target_interface")) if source and source.interface else None
                if source and source.vlanid is not None and parent and re.fullmatch(r"ethernet\d+/\d+", parent):
                    values[key] = f"{parent}.{source.vlanid}"
                    evidence[key] = ["Source VLAN tag and proposed parent allocation"]
        if previous == values:
            break
    provisional = PANMigrationDecisionSet(tuple(replace(item, value=values.get(item.key),
            review_state=PANDecisionReviewState.CONFIRMED if values.get(item.key) else PANDecisionReviewState.PENDING,
            approved_operation="CREATE") for item in decisions.decisions))
    plan = FortiGateToPaloAltoPlanner().plan(config, derived, provisional.to_options(), include_configuration=True)
    # Discover additive deltas using proposed values, never the executable pipeline.
    classifications = classify_target_object_reuse(plan, destination, target_device, allow_additive=True)
    operations = {}
    classification_by_source = {(row["source_vdom"], row.get("source_kind"), row["source_name"], row["family"]): row
                                for row in classifications}
    for key, item in by_key.items():
        operation = None if item.target_field == "vsys" and destination is None else "CREATE"
        family = "interface" if item.target_field == "target_interface" else "zone" if item.target_field == "target_zone" else item.target_field
        classification = classification_by_source.get((item.source_vdom, item.source_kind, item.source_name, family))
        if classification and classification["status"] == "EXACT_MATCH":
            operation = "REUSE"
        elif classification and classification["status"] == "ADDITIVE":
            operation = "CONFIGURE"
        elif destination is not None and item.target_field in {"vsys", "virtual_router"}:
            records = destination.config.scopes if item.target_field == "vsys" else destination.config.virtual_routers
            if any((row.vsys if item.target_field == "vsys" else row.name) == values.get(key)
                   and _device(row) == target_device for row in records):
                operation = "REUSE"
        operations[key] = operation
    provisional = PANMigrationDecisionSet(tuple(replace(item, approved_operation=operations[item.key]) for item in provisional.decisions))
    target_findings = validate_against_target(config, provisional, destination, target_device)
    findings = [row.to_dict() for row in target_findings]
    decision_blockers = {key: [] for key in by_key}
    for finding in target_findings:
        if finding.severity == "error":
            decision_blockers[finding.decision_key].append(finding.message)
    for key, item in by_key.items():
        value = values.get(key)
        if value and (len(value) > 63 or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", value)):
            decision_blockers[key].append("Target name is invalid or exceeds 63 characters")
        classification = classification_by_source.get((item.source_vdom, item.source_kind, item.source_name,
                    "interface" if item.target_field == "target_interface" else "zone"))
        if classification and classification["status"] in {"AMBIGUOUS", "NAME_CONFLICT"}:
            decision_blockers[key].extend(classification.get("evidence", ()) or ("Conflicting destination object",))
    rows = {}
    for key in graph.topological_order():
        item = by_key[key]
        blocked = list(decision_blockers[key])
        missing = [parent for parent in sorted(dependencies[key]) if not values.get(parent)
                   or decision_blockers.get(parent) or (parent in rows and rows[parent].status != "READY")]
        if missing:
            blocked.append("Unresolved prerequisite: " + ", ".join(missing))
        status = "UNSUPPORTED" if item.mode is PANDecisionMode.UNSUPPORTED else "CONFLICT" if decision_blockers[key] else "NEEDS_INPUT" if not values.get(key) or missing else "READY"
        rows[key] = PANDraftDecision(key, item.source_vdom, item.source_kind, item.source_name,
            item.target_field, values.get(key), operations[key] if values.get(key) else None,
            status, values.get(make_decision_key(item.source_vdom, "vdom", item.source_vdom, "vsys")),
            tuple(sorted(dependencies[key])), tuple(evidence.get(key, ())), tuple(blocked),
            key in approved and values.get(key) == by_key[key].value)
    index = build_plan_dependency_index(plan, provisional)
    dispositions, blockers = assess_target_plan(plan, classifications, target_findings, provisional, index)
    validation = validate_plan(plan)
    configuration = []
    # Planned placeholders may omit unresolved target names. Keep source dependencies visible.
    source_refs = {}
    for route in config.static_routes:
        source_refs[(route.vdom or "root", "static_route", str(route.seq_num))] = (route.device,)
    for number, server in enumerate(config.dhcp_servers):
        name = str(server.id if server.id is not None else server.interface or number)
        source_refs[(server.vdom or "root", "dhcp_server", name)] = (server.interface,)
    for policy in config.policies:
        names = tuple(policy.srcintf or ()) + tuple(policy.dstintf or ())
        name = policy.name or str(policy.policy_id)
        for kind in ("policy", "source_nat"):
            source_refs[(policy.vdom or "root", kind, name)] = names
    for vip in config.vips:
        names = [vip.extintf] + [name for policy in config.policies
            if (policy.vdom or "root") == (vip.vdom or "root") and vip.name in (policy.dstaddr or ())
            for name in (policy.srcintf or ())]
        source_refs[(vip.vdom or "root", "vip", vip.name)] = names
    for item in _items(plan):
        key = item_key(item)
        required = list(index.decision_keys_by_item.get(key, ()))
        for name in source_refs.get((item.source_vdom or "root", item.source_kind, item.source_name), ()):
            required.extend(row.key for row in decisions.decisions if row.source_vdom == (item.source_vdom or "root")
                            and row.source_name == name and row.source_kind in {"interface", "zone"})
        required = list(dict.fromkeys(required))
        item_dependencies = ["item:" + parent for parent, children in index.dependents_by_item.items() if key in children]
        reasons = list(item.warnings) if item.status.value != "SUPPORTED" else []
        reasons.extend(blockers.get(key, ()))
        if any(rows[parent].status != "READY" for parent in required if parent in rows):
            reasons.append("Resolve the related mapping decisions")
        valid = (item.source_object_type, item.target_vsys, item.target_name or item.source_name) in validation.renderable_item_keys
        operation = dispositions[key].value
        configuration.append({"group_key": "item:" + key, "item_key": key,
            "source_vdom": item.source_vdom, "source_kind": item.source_kind, "source_name": item.source_name,
            "family": item.source_object_type, "target_name": item.target_name, "target_scope": item.target_vsys,
            "operation": operation if operation != "BLOCK" else None,
            "status": "READY" if valid and operation != "BLOCK" and not reasons else
                "UNSUPPORTED" if item.status.value == "UNSUPPORTED" else
                "CONFLICT" if any(code.startswith("TARGET_") for code in blockers.get(key, ())) else "NEEDS_INPUT",
            "dependencies": list(required) + item_dependencies, "blocking_reasons": reasons,
            "configuration": asdict(item)})
    findings.extend({"code": row.code, "message": row.message} for row in validation.issues)
    if destination is None:
        findings.append({"code": "DESTINATION_UNVERIFIED", "message": "Destination compatibility, collisions, hardware capacity and licensing are unverified."})
    else:
        findings.append({"code": "CAPABILITY_UNVERIFIED", "message": "XML establishes configured objects. Hardware capacity and licensing need engineer verification."})
    return PANMigrationDraft(context, tuple(rows[key] for key in sorted(rows)), tuple(configuration), tuple(findings),
                             design_digest(decisions.to_dict()))


def approve_draft(decisions, draft, selected_groups, *, approved_groups=()):
    """Validate the entire selection before returning any confirmed decision."""
    body = draft.to_dict()
    rows = {row["decision_key"]: row for row in body["decisions"]}
    groups = {**rows, **{row["group_key"]: row for row in body["configuration"]}}
    if (not isinstance(selected_groups, list) or not selected_groups
            or any(not isinstance(key, str) for key in selected_groups)
            or len(set(selected_groups)) != len(selected_groups) or set(selected_groups) - set(groups)):
        raise ValueError("Select unique current proposal groups")
    selected = set(selected_groups)
    for key in selected:
        row = groups[key]
        if row["status"] != "READY":
            raise ValueError("Selected proposal is blocked: " + key)
        if any(parent not in selected and parent not in approved_groups
               and not rows.get(parent, {}).get("approved") for parent in row["dependencies"]):
            raise ValueError("Explicitly include or approve all prerequisite groups")
    context = {**body["context"], "draft_digest": body["digest"]}
    result = []
    for item in decisions.decisions:
        if item.key in selected:
            row = rows[item.key]
            item = replace(item, value=row["proposed_value"], review_state=PANDecisionReviewState.CONFIRMED,
                approved_operation=row["operation"], approval_context=context, evidence_source="ENGINEER",
                evidence_type="APPROVED_DETERMINISTIC_DRAFT", evidence_value=list(row["evidence"]),
                target_object=row["proposed_value"])
        result.append(item)
    return PANMigrationDecisionSet(tuple(result))
