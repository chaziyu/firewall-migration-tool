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
from ..target.name_validation import zone_name_issue
from ..target.target_object_reuse import classify_target_object_reuse
from ..target.target_plan_validation import assess_target_plan, _items, item_key
from ..plan_dependencies import build_plan_dependency_index, policy_order_predecessors, target_identity
from ..target.profile import bind_vip_external_zones
from ..validation import validate_plan, validate_source_interfaces
from ..requirements import build_mapping_requirements
from ..coverage import build_migration_coverage, represented_vip_groups
from ..recommendations.recommendation_engine import build_recommendations
from ..recommendations.support_guidance import _warning_guidance, shared_action_groups
from ..options import PANMigrationOptions
from ..target.profile import MODEL_PORTS, parse_conversion_settings, interface_scope_suggestions, interface_consumers, site_to_site_phase1, management_profile_groups, policy_identity_groups
from ..planning.naming import allocate_plan_names
from ..planning.vpn import vpn_parameter_requirements, represented_vpn_sources, validate_vpn_parameters
from ..planning.policies import inspection_design_groups


def draft_context(source_digest, reference=None, reference_role=None, target_device=None, intent=None,
                  workflow_mode=None, conversion_settings=None):
    mode = "DESTINATION_AWARE" if workflow_mode is None else workflow_mode
    if not isinstance(mode, str):
        raise ValueError("workflow_mode must be OFFLINE_EXPORT or DESTINATION_AWARE")
    mode = {"offline": "OFFLINE_EXPORT", "destination": "DESTINATION_AWARE"}.get(mode, mode)
    if mode not in {"OFFLINE_EXPORT", "DESTINATION_AWARE"}:
        raise ValueError("workflow_mode must be OFFLINE_EXPORT or DESTINATION_AWARE")
    role = reference_role or ("DESTINATION" if reference else None)
    if role not in {None, "DESTINATION", "TEMPLATE"}:
        raise ValueError("reference_role must be DESTINATION, TEMPLATE, or null")
    context = {"source_digest": source_digest, "reference_digest": (reference or {}).get("config_digest"),
            "reference_role": role, "target_device": target_device, "target_serial": (reference or {}).get("serial"),
            "baseline_sha256": (reference or {}).get("baseline_sha256"),
            "baseline_format": (reference or {}).get("baseline_format"),
            "intent": parse_target_intent(intent), "workflow_mode": mode, "schema_version": 1}
    if conversion_settings:
        context['conversion_settings'] = parse_conversion_settings(conversion_settings)
    elif conversion_settings is not None:
        parse_conversion_settings(conversion_settings)
    return context


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
                              intent=None, overrides=None, service_names=None, workflow_mode=None, conversion_settings=None,
                              requirements=None, source_inventory=None):
    context = draft_context(source_digest, reference, reference_role, target_device, intent, workflow_mode, conversion_settings)
    settings = context.get('conversion_settings', {})
    excluded = set(settings.get('excluded_interfaces', ()))
    if excluded - {f'{item.vdom or "root"}/{item.name}' for item in config.interfaces}:
        raise ValueError('Excluded interfaces must select current source interfaces')
    if context["workflow_mode"] == "OFFLINE_EXPORT" and (reference or target is not None or target_device):
        raise ValueError("Offline export cannot use destination or template evidence")
    overrides = overrides or {}
    by_key = {item.key: item for item in decisions.decisions}
    if not isinstance(overrides, dict) or set(overrides) - set(by_key):
        raise ValueError("draft_overrides must select current decision keys")
    if any(not isinstance(value, str) or not value.strip() for value in overrides.values()):
        raise ValueError("draft overrides must be non-empty strings")
    context["overrides"] = {key: value.strip() for key, value in overrides.items()}
    service_names = PANMigrationOptions(service_names={} if service_names is None else service_names).service_names
    context["service_names"] = service_names
    if requirements is None:
        requirements = build_mapping_requirements(config, derived, include_configuration=True)
    graph = build_decision_graph(config, derived, decisions, requirements)
    dependencies = {row.decision_key: set(row.depends_on) for row in graph.dependencies}
    for item in decisions.decisions:
        if item.source_kind != "vdom":
            vsys_key = make_decision_key(item.source_vdom, "vdom", item.source_vdom, "vsys")
            if vsys_key in by_key:
                dependencies[item.key].add(vsys_key)
    interfaces = {(item.vdom or "root", item.name): item for item in config.interfaces}
    vpns = site_to_site_phase1(config)
    tunnel_sources = sorted(identity for identity, item in interfaces.items() if (item.type or '').lower() == 'tunnel' and identity in vpns)
    validate_vpn_parameters(config, settings, derived)
    inspection_groups = inspection_design_groups(config)
    if set(settings.get('security_profiles', {})) - {row['identity'] for row in inspection_groups}:
        raise ValueError('Security profile assignments must select current source inspection groups')
    if set(settings.get('existing_vpns', ())) - {f'{vdom}/{name}' for vdom, name in tunnel_sources}:
        raise ValueError('Existing VPN prerequisites must select supported explicit site-to-site tunnel interfaces')
    if set(settings.get('management_profiles', {})) - {f'{vdom}/{name}' for vdom, name in interfaces}:
        raise ValueError('Management profiles must select current source interfaces')
    loopbacks = sorted(identity for identity, item in interfaces.items() if (item.type or "").casefold() == "loopback")
    aggregates = sorted(identity for identity, item in interfaces.items() if (item.type or "").casefold() == "aggregate")
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
    vdoms = sorted({item.source_vdom for item in decisions.decisions})
    destination = target if context["reference_role"] == "DESTINATION" and target_device else None
    evidence = {key: ["Explicit engineer allocation" if key in explicit else "Existing engineer decision"] for key in values}
    if context["workflow_mode"] == "OFFLINE_EXPORT":
        reserved_ports = {value.split(".", 1)[0] for key, value in values.items()
                          if by_key[key].target_field == "target_interface"}
        number = 1
        port_pool = MODEL_PORTS.get(settings.get('target_model'))
        ports = []
        consumers = interface_consumers(config)
        for identity, source in sorted(interfaces.items(), key=lambda row: (
                bool(port_pool) and not (row[0] in consumers or row[1].ip or row[1].allowaccess),
                row[0][0], [int(part) if part.isdigit() else part
                            for part in re.split(r"(\d+)", row[0][1])])):
            key = make_decision_key(identity[0], "interface", identity[1], "target_interface")
            if (key not in by_key or key in values or by_key[key].mode is PANDecisionMode.UNSUPPORTED
                    or (source.type or "").casefold() not in {"physical", "ethernet"}
                    or source.interface or source.vlanid is not None or source.members
                    or f'{identity[0]}/{identity[1]}' in excluded):
                continue
            match = re.fullmatch(r"port([1-9]\d*)", identity[1])
            preferred = f"ethernet1/{int(match[1])}" if match else None
            ports.append((key, preferred))
        # Reserve numbered proposals before named ports; collisions require an explicit choice.
        claims = {}
        for key, preferred in ports:
            if preferred:
                claims.setdefault(preferred, []).append(key)
        for key, preferred in ports:
            if preferred:
                if preferred in reserved_ports or len(claims[preferred]) > 1:
                    evidence[key] = [f"Preferred port {preferred} is claimed by another interface. Choose a distinct target port explicitly."]
                    continue
                if port_pool is not None and preferred not in port_pool:
                    evidence[key] = [f"Preferred port {preferred} is outside the selected target port pool. Review migration scope or choose an available port explicitly."]
                    continue
                values[key] = preferred
                reserved_ports.add(preferred)
        reserved_ports.update(claims)
        for key, preferred in ports:
            if preferred:
                if key not in values:
                    continue
            else:
                while f"ethernet1/{number}" in reserved_ports:
                    number += 1
                if port_pool is not None and f'ethernet1/{number}' not in port_pool:
                    evidence[key] = ['Target port pool exhausted. Review migration scope or provide a different supported target design.']
                    continue
                values[key] = f"ethernet1/{number}"
                reserved_ports.add(values[key])
                number += 1
            evidence[key] = ["Automatic offline port allocation proposal; target port availability, hardware and cabling are unverified. Engineer approval is required."]
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
                if not compatible and len(options) == 1 and len(vdoms) == 1:
                    compatible = list(options)
            if len(compatible) == 1:
                values[key] = compatible[0]["value"]
                evidence[key] = list(compatible[0].get("strong_evidence", ())) or ["Unique reference scope"]
                continue
            if item.target_field == "vsys" and context["workflow_mode"] == "OFFLINE_EXPORT":
                values[key] = f"vsys{vdoms.index(item.source_vdom) + 1}"
                evidence[key] = ["Proposed VDOM ownership; engineer must confirm the target VSYS"]
            elif item.target_field == "virtual_router":
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
                if source and (source.type or "").casefold() == "loopback":
                    used = set(values.values())
                    number = loopbacks.index((item.source_vdom, item.source_name)) + 1
                    while f"loopback.{number}" in used:
                        number += 1
                    values[key] = f"loopback.{number}"
                    evidence[key] = ["Proposed loopback identifier; engineer must confirm identifier and ownership"]
                elif (item.source_vdom, item.source_name) in tunnel_sources:
                    used = set(values.values())
                    if destination is not None:
                        used.update(row.name for row in (*destination.config.interfaces, *destination.config.interface_units) if _device(row) == target_device)
                    number = tunnel_sources.index((item.source_vdom, item.source_name)) + 1
                    while f'tunnel.{number}' in used:
                        number += 1
                    values[key] = f'tunnel.{number}'
                    evidence[key] = ['Proposed site-to-site IPsec tunnel identifier. Gateway, credentials and selectors remain separate prerequisites.']
                elif source and (source.type or "").casefold() == "aggregate":
                    number = aggregates.index((item.source_vdom, item.source_name)) + 1
                    while f"ae{number}" in values.values():
                        number += 1
                    values[key] = f"ae{number}"
                    evidence[key] = ["Proposed aggregate identifier; physical member allocations and ownership require engineer approval"]
                elif source and source.vlanid is not None and parent and re.fullmatch(r"ethernet\d+/\d+|ae(?:[1-9]|1[0-6])", parent):
                    values[key] = f"{parent}.{source.vlanid}"
                    evidence[key] = ["Proposed subinterface identifier using the VLAN tag as a suffix; identifier and tag are independent"]
        if previous == values:
            break
    provisional = PANMigrationDecisionSet(tuple(replace(item, value=values.get(item.key),
            review_state=PANDecisionReviewState.CONFIRMED if values.get(item.key) else PANDecisionReviewState.PENDING,
            approved_operation="CREATE") for item in decisions.decisions))
    planner_options = replace(provisional.to_options(), conversion_settings=settings)
    plan = FortiGateToPaloAltoPlanner().plan(config, derived, planner_options, include_configuration=True,
                                          requirements=requirements)
    if service_names:
        eligible = {(item.source_vdom or "root", item.source_name) for item in plan.services if item.status.value == "SUPPORTED"}
        if any((vdom, name) not in eligible for vdom, names in service_names.items() for name in names):
            raise ValueError("Service name overrides must select current supported services")
        plan = FortiGateToPaloAltoPlanner().plan(config, derived,
            replace(planner_options, service_names=service_names), include_configuration=True, requirements=requirements)
    plan = allocate_plan_names(plan, destination, target_device, service_names)
    plan = bind_vip_external_zones(plan, settings, destination, target_device)
    # Discover additive deltas using proposed values, never the executable pipeline.
    classifications = classify_target_object_reuse(plan, destination, target_device, allow_additive=True) if destination is not None else ()
    operations = {}
    classification_by_source = {(row["source_vdom"], row.get("source_kind"), row["source_name"], row["family"]): row
                                for row in classifications}
    for zone in plan.zones:
        classification = classification_by_source.get((zone.source_vdom, zone.source_kind, zone.source_name, 'zone'))
        if classification:
            for ref in zone.source_contributors:
                classification_by_source[(ref.source_vdom, ref.source_kind, ref.source_name, 'zone')] = classification
    classification_by_item = {(row['source_vdom'], row.get('source_kind'), row['source_name'], row['family'], row.get('target_name')): row for row in classifications}
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
    findings.extend({'code': 'VIP_EXTERNAL_ZONE_REQUIRED', 'source_vdom': vip.vdom or 'root',
        'identity': vip.name, 'message': 'Choose the original-packet destination zone before destination translation.'}
        for vip in config.vips if not vip.extintf or vip.extintf == 'any'
        or vip.name in settings.get('vip_external_zones', {}).get(vip.vdom or 'root', {}))
    findings.extend({'code': 'EFFECTIVE_SOURCE_VALUE', 'source_vdom': row.vdom,
        'source_kind': row.kind, 'identity': f'{row.vdom}/{row.name}',
        'message': f'{row.kind} {row.name}: {row.field}={row.value} is a documented FortiOS {row.version} effective value, not explicit source state. Reference: {row.reference}'}
        for row in getattr(derived, 'effective_values', ()))
    findings.extend(validate_source_interfaces(config))
    findings.extend({'code': 'SECURITY_PROFILE_REQUIRED', **group} for group in inspection_groups)
    findings.extend({'code': 'VPN_PARAMETERS_REQUIRED', 'message': 'Supply reviewed target values for absent source parameters; no defaults are inferred.',
        **group} for group in vpn_parameter_requirements(config, derived))
    findings.extend({'code': 'VPN_PREREQUISITE', 'identity': f'{vdom}/{name}',
        'message': 'Existing target VPN must use the reviewed tunnel identifier, gateway, credentials, selectors and crypto settings.'}
        for vdom, name in tunnel_sources)
    findings.extend({'code': 'SOURCE_INTERFACE_MISSING', 'source_vdom': row.source_vdom, 'source_kind': 'interface',
        'source_name': row.source_name, 'message': f'{row.source_name} is referenced but has no explicit source interface. Review the incomplete source relationship.'}
        for row in decisions.decisions if row.source_kind == 'interface' and row.target_field == 'target_interface'
        and (row.source_vdom, row.source_name) not in interfaces)
    findings.extend({'code': 'MANAGEMENT_PROFILE_REQUIRED', 'identity': f'{item.vdom or "root"}/{item.name}',
        'message': 'Explicit source administrative protocols: ' + ', '.join(item.allowaccess)}
        for item in config.interfaces if item.allowaccess)
    findings.extend({'code': 'MANAGEMENT_PROFILE_GROUP', **group} for group in management_profile_groups(config))
    findings.extend({'code': 'IDENTITY_MAPPING_REQUIRED', **group} for group in policy_identity_groups(config))
    findings.extend({"code": "TARGET_RULE_PLACEMENT_UNVERIFIED",
        "message": f"Target {row['family'].replace('_', ' ')} placement for {row['target_name']!r} is unverified because the applicable rulebase is populated.",
        "source_vdom": row.get("source_vdom"), "source_name": row.get("source_name"),
        "target_name": row.get("target_name"), "evidence": row.get("evidence", [])}
        for row in classifications if row.get("status") == "ORDER_UNVERIFIED")
    decision_blockers = {key: [] for key in by_key}
    if context["workflow_mode"] == "OFFLINE_EXPORT":
        ownership = {}
        for key, item in by_key.items():
            if item.target_field in {"vsys", "virtual_router"} and values.get(key):
                ownership.setdefault((item.target_field, values[key]), []).append(key)
        for keys in ownership.values():
            if len(keys) > 1:
                for key in keys:
                    decision_blockers[key].append("Conflicting VDOM ownership; allocate distinct target scopes")
    for finding in target_findings:
        if finding.severity == "error":
            decision_blockers[finding.decision_key].append(finding.message)
    for key, item in by_key.items():
        value = values.get(key)
        if (value and item.target_field == 'target_interface' and settings.get('target_model')
                and value.split('.', 1)[0].startswith('ethernet') and value.split('.', 1)[0] not in MODEL_PORTS[settings['target_model']]):
            decision_blockers[key].append('Target interface is outside the selected hardware port pool')
        if value and item.target_field == "target_zone":
            if issue := zone_name_issue(value):
                decision_blockers[key].append(issue)
        elif value and item.target_field == "virtual_router":
            if len(value) > 31 or not re.fullmatch(r"[A-Za-z0-9_ -]+", value):
                decision_blockers[key].append("Virtual-router name must contain 1 to 31 letters, numbers, spaces, hyphens or underscores")
        elif value and (len(value) > 63 or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", value)):
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
        source = interfaces.get((item.source_vdom, item.source_name)) if item.source_kind == 'interface' else None
        unsupported_tunnel = source and (source.type or '').lower() == 'tunnel' and (item.source_vdom, item.source_name) not in vpns
        status = "UNSUPPORTED" if item.mode is PANDecisionMode.UNSUPPORTED or unsupported_tunnel or (item.source_kind == 'interface' and f'{item.source_vdom}/{item.source_name}' in excluded) else "CONFLICT" if decision_blockers[key] else "NEEDS_INPUT" if not values.get(key) or missing else "READY"
        if unsupported_tunnel:
            blocked.append('Special or remote-access tunnel requires a separate target VPN design')
        if status == 'UNSUPPORTED' and f'{item.source_vdom}/{item.source_name}' in excluded:
            blocked.append('Explicitly excluded from this conversion; dependent configuration remains blocked')
        rows[key] = PANDraftDecision(key, item.source_vdom, item.source_kind, item.source_name,
            item.target_field, values.get(key), operations[key] if values.get(key) else None,
            status, values.get(make_decision_key(item.source_vdom, "vdom", item.source_vdom, "vsys")),
            tuple(sorted(dependencies[key])), tuple(evidence.get(key, ())), tuple(blocked),
            key in approved and values.get(key) == by_key[key].value)
    index = build_plan_dependency_index(plan, provisional)
    parents_by_item = {}
    for parent, children in index.dependents_by_item.items():
        for child in children:
            parents_by_item.setdefault(child, []).append("item:" + parent)
    dispositions, blockers = assess_target_plan(plan, classifications, target_findings, provisional, index)
    validation = validate_plan(plan)
    naming_issues_by_source = {}
    for issue in validation.issues:
        if issue.code.startswith("duplicate_target") or issue.code == "invalid_target_object_name":
            ref = issue.source
            naming_issues_by_source.setdefault((ref.source_vdom or "root", ref.source_kind, ref.source_name), []).append(issue.message)
    configuration = []
    predecessors = policy_order_predecessors(plan)
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
        source_interfaces = (() if item.source_object_type == 'address' else
            source_refs.get((item.source_vdom or "root", item.source_kind, item.source_name), ()))
        for name in source_interfaces:
            required.extend(row.key for row in decisions.decisions if row.source_vdom == (item.source_vdom or "root")
                            and row.source_name == name and row.source_kind in {"interface", "zone"})
        required = list(dict.fromkeys(required))
        item_dependencies = parents_by_item.get(key, [])
        reasons = list(item.warnings) if item.status.value != "SUPPORTED" else []
        naming_issues = naming_issues_by_source.get((item.source_vdom or "root", item.source_kind, item.source_name), ())
        reasons.extend(naming_issues)
        if item.source_object_type == "security_rule":
            predecessor = predecessors.get(key)
            if predecessor is not None and (dispositions[item_key(predecessor)].value == "BLOCK"
                    or target_identity(predecessor) not in validation.renderable_item_keys):
                reasons.append(f"Preceding active policy {predecessor.source_vdom} / {predecessor.source_name} "
                               f"(ID {predecessor.source_policy_id}) is blocked")
        reasons.extend(blockers.get(key, ()))
        if any(rows[parent].status != "READY" for parent in required if parent in rows):
            reasons.append("Resolve the related mapping decisions")
        valid = target_identity(item) in validation.renderable_item_keys
        operation = dispositions[key].value
        causes = [_warning_guidance(item, warning, frozenset(by_key)).to_dict()
                  for warning in item.warnings]
        manual = any(cause["resolution_type"] not in {"MISSING_MAPPING", "TARGET_CONFLICT"}
                     or (cause["resolution_type"] == "MISSING_MAPPING" and not cause["decision_key"])
                     for cause in causes)
        configuration.append({"group_key": "item:" + key, "item_key": key,
            "source_vdom": item.source_vdom, "source_kind": item.source_kind, "source_name": item.source_name,
            "family": item.source_object_type, "target_name": item.target_name, "target_scope": target_identity(item)[1],
            "operation": operation if operation != "BLOCK" else None,
            "status": "READY" if valid and operation != "BLOCK" and not reasons else
                "UNSUPPORTED" if item.status.value == "UNSUPPORTED" or manual else
                "CONFLICT" if naming_issues or any(code.startswith("TARGET_") for code in blockers.get(key, ())) else "NEEDS_INPUT",
            "dependencies": list(required) + item_dependencies, "blocking_reasons": reasons,
            "configuration": asdict(item), "causes": causes})
        comparison = classification_by_item.get((item.source_vdom or "root", item.source_kind, item.source_name, item.source_object_type, item.target_name))
        if comparison and comparison['status'] != 'NO_MATCH':
            configuration[-1]['target_comparison'] = comparison
    findings.extend(shared_action_groups(configuration))
    coverage = build_migration_coverage(config,
        build_recommendations(config, derived, provisional, destination, target_device), plan=plan, options=planner_options,
        source_inventory=source_inventory,
        planned_vpn_sources=represented_vpn_sources(plan),
        planned_vip_groups=represented_vip_groups(config, plan, {row['item_key'] for row in configuration if row['status'] == 'READY'}))
    for number, gap in enumerate(coverage["unplanned"]):
        pending = gap['readiness'] == 'PENDING'
        mapping_key = make_decision_key(gap['source_vdom'], 'interface', gap['source_name'], 'target_interface')
        configuration.append({"group_key": f"coverage:{number}",
            "source_vdom": gap["source_vdom"], "source_kind": gap["source_kind"],
            "source_name": gap["source_name"], "family": gap["family"],
            "target_name": None, "target_scope": None, "operation": None,
            "status": "NEEDS_INPUT" if pending else "UNSUPPORTED",
            "dependencies": [mapping_key] if pending and mapping_key in rows else [],
            "blocking_reasons": [gap["reason"], "Review target placement; approving supported groups leaves a partial migration." if pending
                                 else "Manual implementation required; approving supported groups leaves a partial migration."]})
    findings.extend({"code": row.code, "message": row.message} for row in validation.issues)
    findings.extend({'code': 'SCOPE_SUGGESTION', 'message': row['reason'], 'identity': row['identity']} for row in interface_scope_suggestions(config))
    if destination is None:
        findings.append({"code": "DESTINATION_UNVERIFIED", "message": "Destination compatibility, collisions, hardware capacity and licensing are unverified."})
    else:
        findings.append({"code": "CAPABILITY_UNVERIFIED", "message": "XML establishes configured objects. Hardware capacity and licensing need engineer verification."})
    for finding in findings:
        if finding['code'].startswith('SOURCE_'):
            mapping_key = make_decision_key(finding['source_vdom'], 'interface', finding['source_name'], 'target_interface')
            finding['affected_keys'] = [row['group_key'] for row in configuration if mapping_key in row['dependencies']]
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
