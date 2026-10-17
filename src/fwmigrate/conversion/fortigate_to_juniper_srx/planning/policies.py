"""Fail-closed planning for ordered FortiGate IPv4 L3/L4 policies."""

from itertools import product

from fwmigrate.vendors.fortigate.relationships.references import ReferenceKind

from ..models import SRXFinding, SRXPlanItem
from .naming import decision_key, item_key, target_name


_ADDRESS_KINDS = (ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP)
_SERVICE_KINDS = (ReferenceKind.SERVICE, ReferenceKind.SERVICE_GROUP)
_UNSUPPORTED_POLICY_SECTIONS = {
    "firewall policy6", "firewall proxy-policy", "firewall multicast-policy",
    "firewall local-in-policy",
}
_UNSUPPORTED_FIELDS = (
    "groups", "users", "vpntunnel", "internet_service", "internet_service_name",
    "internet_service_group", "internet_service_custom", "internet_service_src",
    "internet_service_src_name", "internet_service_src_group", "internet_service_src_custom",
    "inspection_mode", "profile_type", "profile_group", "profile_protocol_options",
    "per_ip_shaper", "av_profile", "ips_sensor", "application_list", "webfilter_profile",
    "dnsfilter_profile", "ssl_ssh_profile",
)


def _finding(code, vdom):
    return SRXFinding(code, code.replace("_", " ").capitalize(), vdom,
                      "source_evidence", "FortiGate")


def _inventory_blockers(source, source_inventory, vdom):
    if source_inventory is None:
        return ["SOURCE_INVENTORY_NOT_PROVIDED"], [_finding("SOURCE_INVENTORY_NOT_PROVIDED", vdom)]

    blockers = []
    findings = []
    typed_policy_ids = {str(policy.policy_id) for policy in source.policies if policy.vdom == vdom}
    for record in source_inventory:
        if getattr(record, "vdom", None) != vdom:
            continue
        path = str(getattr(record, "source_path", "")).strip().lower()
        values = getattr(record, "values", {}) or {}
        explicit = set(getattr(record, "explicit_fields", ()) or ())
        commands = getattr(record, "commands", ()) or ()
        if getattr(record, "object_name", None) is None and not explicit and not commands:
            continue
        if path in {"firewall central-snat-map", "router policy"}:
            status_disabled = "status" in explicit and str(values.get("status", "")).lower() == "disable"
            if not status_disabled:
                code = "CENTRAL_SNAT_EVIDENCE_UNTRANSLATED" if path == "firewall central-snat-map" else "POLICY_ROUTING_EVIDENCE_UNTRANSLATED"
                blockers.append(code)
                findings.append(_finding(code, vdom))
        elif path in _UNSUPPORTED_POLICY_SECTIONS:
            blockers.append("UNSUPPORTED_POLICY_SECTION_PRESENT")
            findings.append(_finding("UNSUPPORTED_POLICY_SECTION_PRESENT", vdom))
        elif path == "firewall policy" and str(getattr(record, "object_name", "")) not in typed_policy_ids:
            blockers.append("UNREPRESENTED_POLICY_SOURCE_EVIDENCE")
            findings.append(_finding("UNREPRESENTED_POLICY_SOURCE_EVIDENCE", vdom))
    return list(dict.fromkeys(blockers)), list({finding.code: finding for finding in findings}.values())


def _zone_target(source, derived, options, vdom, name, zone_items):
    reference = derived.references.resolve_any(
        vdom=vdom, name=name, kinds=(ReferenceKind.ZONE, ReferenceKind.INTERFACE),
    )
    if reference is None or reference.predefined:
        return (), (), ("POLICY_INTERFACE_OR_ZONE_UNRESOLVED",)
    if reference.kind is ReferenceKind.ZONE:
        zone_name = reference.name
    elif reference.kind is ReferenceKind.INTERFACE:
        memberships = [zone for zone in source.zones if zone.vdom == vdom and name in (zone.members or ())]
        if len(memberships) != 1 or "members" not in memberships[0].explicit_fields:
            return (), (), ("POLICY_INTERFACE_REQUIRES_ONE_EXPLICIT_ZONE",)
        zone_name = memberships[0].name
    else:
        return (), (), ("POLICY_INTERFACE_OR_ZONE_UNSUPPORTED",)

    item = zone_items.get(zone_name)
    target = options.zones.get(vdom, {}).get(zone_name)
    if item is None or target is None:
        return (), (), ("POLICY_TARGET_ZONE_MAPPING_REQUIRED",)
    blockers = ("POLICY_TARGET_ZONE_BLOCKED",) if item.blockers else ()
    return (target,), (item.key,), blockers


def _match_values(derived, items_by_family, vdom, names, kinds, match_kind):
    if names is None or not names:
        return (), (), (f"POLICY_{match_kind.upper()}_NOT_EXPLICIT",)
    values, dependencies, blockers = [], [], []
    for name in names:
        reference = derived.references.resolve_any(vdom=vdom, name=name, kinds=kinds)
        if reference is None:
            blockers.append(f"POLICY_{match_kind.upper()}_REFERENCE_UNRESOLVED")
            continue
        if reference.predefined:
            if match_kind in {"source_address", "destination_address"} and name.casefold() == "all":
                values.append("any-ipv4")
            elif match_kind == "service" and name.casefold() == "all":
                values.append("any")
            else:
                blockers.append(f"POLICY_PREDEFINED_{match_kind.upper()}_UNVERIFIED")
            continue

        family = {
            ReferenceKind.ADDRESS: "address",
            ReferenceKind.ADDRESS_GROUP: "address_group",
            ReferenceKind.SERVICE: "service",
            ReferenceKind.SERVICE_GROUP: "service_group",
        }.get(reference.kind)
        item = items_by_family.get((family, reference.name)) if family else None
        if item is None and reference.kind is ReferenceKind.SERVICE:
            item = items_by_family.get(("service_group", reference.name))
        if item is None:
            blockers.append(f"POLICY_{match_kind.upper()}_OUTSIDE_SELECTED_SCOPE")
            continue
        values.append(item.target_name)
        dependencies.append(item.key)
        if item.blockers:
            blockers.append(f"POLICY_{match_kind.upper()}_OBJECT_BLOCKED")
    return tuple(dict.fromkeys(values)), tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(blockers))


def _policy_blockers(policy, source_inventory_blockers):
    blockers = list(source_inventory_blockers)
    if policy.raw_extra:
        blockers.append("POLICY_HAS_UNSUPPORTED_SOURCE_SETTINGS")

    required = {"srcintf", "dstintf", "srcaddr", "dstaddr", "service", "schedule",
                "action", "status", "nat", "utm_status", "logtraffic",
                "srcaddr_negate", "dstaddr_negate", "service_negate"}
    if not required <= policy.explicit_fields:
        blockers.append("POLICY_REQUIRED_FIELDS_NOT_EXPLICIT")
    for field in ("srcaddr_negate", "dstaddr_negate", "service_negate"):
        if getattr(policy, field) != "disable":
            blockers.append("POLICY_NEGATION_UNSUPPORTED_OR_UNCONFIRMED")
    if policy.action not in {"accept", "deny"}:
        blockers.append("POLICY_ACTION_UNSUPPORTED_OR_UNCONFIRMED")
    if policy.status not in {"enable", "disable"}:
        blockers.append("POLICY_STATUS_UNSUPPORTED_OR_UNCONFIRMED")
    if policy.nat != "disable" or any(getattr(policy, field) not in {None, "disable"}
                                       for field in ("nat64", "nat46", "natinbound", "natoutbound")):
        blockers.append("POLICY_NAT_REQUIRES_SEPARATE_SUPPORT")
    if policy.ippool not in {None, "disable"} or policy.natip or policy.poolname or policy.poolname6:
        blockers.append("POLICY_TRANSLATION_SETTINGS_UNSUPPORTED")
    if policy.utm_status != "disable" or any(getattr(policy, field) for field in _UNSUPPORTED_FIELDS):
        blockers.append("POLICY_SECURITY_OR_IDENTITY_SETTINGS_UNSUPPORTED")
    if policy.logtraffic not in {"all", "disable"}:
        blockers.append("POLICY_LOGGING_MODE_UNSUPPORTED_OR_UNCONFIRMED")
    if policy.srcaddr6 or policy.dstaddr6 or policy.srcaddr6_negate not in {None, "disable"} or policy.dstaddr6_negate not in {None, "disable"}:
        blockers.append("POLICY_IPV6_MATCH_UNSUPPORTED")
    if policy.service_negate == "enable" or policy.srcaddr_negate == "enable" or policy.dstaddr_negate == "enable":
        blockers.append("POLICY_NEGATED_MATCH_UNSUPPORTED")
    return list(dict.fromkeys(blockers))


def plan_policies(source, derived, options, vdom, base_items, schedule_items, source_inventory=None):
    inventory_blockers, findings = _inventory_blockers(source, source_inventory, vdom)
    items_by_family = {(item.family, item.source_name): item for item in base_items}
    zone_items = {item.source_name: item for item in base_items if item.family == "zone"}
    schedule_by_name = {item.source_name: item for item in schedule_items}
    policy_id_counts = {}
    for policy in source.policies:
        if policy.vdom == vdom and policy.policy_id is not None:
            policy_id_counts[policy.policy_id] = policy_id_counts.get(policy.policy_id, 0) + 1
    previous_by_pair = {}
    result = []
    unknown_order_scope = False

    for order, policy in enumerate(item for item in source.policies if item.vdom == vdom):
        blockers = _policy_blockers(policy, inventory_blockers)
        if policy.policy_id is not None and policy_id_counts[policy.policy_id] > 1:
            blockers.append("DUPLICATE_SOURCE_POLICY_ID")
        source_zones, source_zone_deps, source_zone_blockers = [], [], []
        destination_zones, destination_zone_deps, destination_zone_blockers = [], [], []
        if policy.srcintf is None or not policy.srcintf:
            source_zone_blockers.append("POLICY_SOURCE_INTERFACE_NOT_EXPLICIT")
        else:
            for name in policy.srcintf:
                values, deps, errors = _zone_target(source, derived, options, vdom, name, zone_items)
                source_zones.extend(values)
                source_zone_deps.extend(deps)
                source_zone_blockers.extend(errors)
        if policy.dstintf is None or not policy.dstintf:
            destination_zone_blockers.append("POLICY_DESTINATION_INTERFACE_NOT_EXPLICIT")
        else:
            for name in policy.dstintf:
                values, deps, errors = _zone_target(source, derived, options, vdom, name, zone_items)
                destination_zones.extend(values)
                destination_zone_deps.extend(deps)
                destination_zone_blockers.extend(errors)
        source_zones = tuple(dict.fromkeys(source_zones))
        destination_zones = tuple(dict.fromkeys(destination_zones))
        blockers.extend(source_zone_blockers)
        blockers.extend(destination_zone_blockers)

        sources, source_deps, source_errors = _match_values(
            derived, items_by_family, vdom, policy.srcaddr, _ADDRESS_KINDS, "source_address",
        )
        destinations, destination_deps, destination_errors = _match_values(
            derived, items_by_family, vdom, policy.dstaddr, _ADDRESS_KINDS, "destination_address",
        )
        applications, application_deps, application_errors = _match_values(
            derived, items_by_family, vdom, policy.service, _SERVICE_KINDS, "service",
        )
        blockers.extend((*source_errors, *destination_errors, *application_errors))

        schedule_name = policy.schedule
        schedule_deps = []
        if not schedule_name:
            blockers.append("POLICY_SCHEDULE_NOT_EXPLICIT")
        elif schedule_name.casefold() == "always":
            reference = derived.references.resolve_any(
                vdom=vdom, name=schedule_name,
                kinds=(ReferenceKind.SCHEDULE, ReferenceKind.SCHEDULE_GROUP),
            )
            if reference is None or not reference.predefined:
                blockers.append("POLICY_ALWAYS_SCHEDULE_NOT_CONFIRMED")
            schedule_name = None
        else:
            reference = derived.references.resolve_any(
                vdom=vdom, name=schedule_name,
                kinds=(ReferenceKind.SCHEDULE, ReferenceKind.SCHEDULE_GROUP),
            )
            schedule_item = schedule_by_name.get(schedule_name)
            if reference is None or reference.predefined or reference.kind is not ReferenceKind.SCHEDULE or schedule_item is None:
                blockers.append("POLICY_SCHEDULE_UNRESOLVED_OR_UNSUPPORTED")
            else:
                schedule_name = schedule_item.target_name
                schedule_deps.append(schedule_item.key)
                if schedule_item.blockers:
                    blockers.append("POLICY_SCHEDULE_BLOCKED")

        if unknown_order_scope:
            blockers.append("EARLIER_POLICY_SCOPE_UNRESOLVED")
        if not source_zones or not destination_zones:
            unknown_order_scope = True

        pairs = tuple(product(source_zones, destination_zones))
        if not pairs:
            pairs = (("unresolved", "unresolved"),)

        for pair_index, (from_zone, to_zone) in enumerate(pairs):
            pair_key = (from_zone, to_zone)
            pair_blockers = list(blockers)
            if from_zone == "unresolved" or to_zone == "unresolved":
                pair_blockers.append("POLICY_ZONE_PAIR_UNRESOLVED")
            pair_name = f"{order}-{policy.policy_id or ''}-{from_zone}-{to_zone}"
            identity = f"{order}:{policy.policy_id or ''}:{from_zone}:{to_zone}"
            key = item_key(vdom, "policy", identity)
            dependencies = [*source_zone_deps, *destination_zone_deps, *source_deps,
                            *destination_deps, *application_deps, *schedule_deps]
            if pair_key in previous_by_pair:
                dependencies.append(previous_by_pair[pair_key])
            item = SRXPlanItem(
                key=key,
                family="policy",
                source_vdom=vdom,
                source_name=policy.name or str(policy.policy_id or order + 1),
                target_name=target_name("policy", vdom, pair_name),
                settings=(
                    ("from_zone", from_zone), ("to_zone", to_zone),
                    ("source_addresses", sources), ("destination_addresses", destinations),
                    ("applications", applications), ("action", "permit" if policy.action == "accept" else "deny"),
                    ("schedule", schedule_name), ("disabled", policy.status == "disable"),
                    ("logging", policy.logtraffic), ("policy_id", policy.policy_id),
                ),
                dependencies=tuple(dict.fromkeys(dependencies)),
                decision_keys=(decision_key(vdom, "policy", policy.name or str(policy.policy_id), "source_order"),),
                blockers=tuple(dict.fromkeys(pair_blockers)),
                source_order=order * 1000 + pair_index,
            )
            result.append(item)
            previous_by_pair[pair_key] = key

    return result, findings
