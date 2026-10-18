"""Fail-closed NAT coverage for FortiGate to Juniper SRX."""

from collections import Counter, defaultdict
from dataclasses import replace

from ..models import SRXFinding, SRXPlanItem
from .naming import item_key, target_name
from .fixed_pool_nat import plan_fixed_pool_nat


_UNSUPPORTED_NAT_SECTIONS = {
    "firewall ippool", "firewall ippool6", "firewall vip", "firewall vip6",
    "firewall vipgrp", "firewall vipgrp6",
}


def _nat_enabled(policy):
    values = (policy.nat, policy.nat64, policy.nat46, policy.natinbound, policy.natoutbound)
    return any(value is not None and str(value).lower() != "disable" for value in values) or bool(
        policy.natip or policy.poolname or policy.poolname6
    ) or policy.ippool not in {None, "disable"}


def _nat_blockers(policy, entries, duplicate_policy_id):
    blockers = []
    if policy.policy_id is None or duplicate_policy_id:
        blockers.append("SOURCE_NAT_POLICY_ID_MISSING_OR_AMBIGUOUS")
    if len(entries) != 1:
        blockers.append("SOURCE_NAT_ENTRY_MISSING_OR_MULTIPLE")
    for entry in entries:
        if entry.issues:
            blockers.append("SOURCE_NAT_SOURCE_EVIDENCE_REQUIRES_REVIEW")
        if entry.policy_disabled or policy.status == "disable":
            blockers.append("SOURCE_NAT_SOURCE_POLICY_DISABLED")
        if entry.translation_type == "interface_address":
            blockers.append("SOURCE_NAT_PORT_BEHAVIOR_NOT_EXPLICIT")
        elif entry.translation_type == "ip_pool":
            blockers.extend((
                "SOURCE_NAT_POOL_PORT_BEHAVIOR_NOT_EXPLICIT",
                "SOURCE_NAT_POOL_RETURN_ROUTE_OR_PROXY_ARP_REQUIRED",
            ))
        else:
            blockers.append("SOURCE_NAT_TRANSLATION_TYPE_UNSUPPORTED")
    # FortiOS policy source-port preservation and Junos source NAT allocation
    # are not equivalent from the fields currently extracted by this pair.
    if not entries:
        blockers.append("SOURCE_NAT_TRANSLATION_NOT_NORMALIZED")
    return list(dict.fromkeys(blockers))


def plan_nat(source, derived, vdom, policies, source_inventory=None, *, options=None):
    entries_by_policy = defaultdict(list)
    for entry in derived.nat:
        if entry.vdom == vdom:
            entries_by_policy[entry.policy_id].append(entry)

    policy_id_counts = Counter(
        policy.policy_id for policy in source.policies
        if policy.vdom == vdom and policy.policy_id is not None
    )
    source_policies = [
        policy for policy in source.policies
        if policy.vdom == vdom and _nat_enabled(policy)
    ]
    planned_by_policy_id = defaultdict(list)
    for item in policies:
        policy_id = dict(item.settings).get("policy_id")
        if policy_id is not None:
            planned_by_policy_id[policy_id].append(item)

    items = []
    links = {}
    policy_blockers = defaultdict(list)
    findings = []
    for order, policy in enumerate(source_policies):
        entries = entries_by_policy.get(policy.policy_id, [])
        candidate_policies = planned_by_policy_id.get(policy.policy_id, [])
        duplicate_id = policy_id_counts.get(policy.policy_id, 0) != 1
        blockers = _nat_blockers(policy, entries, duplicate_id)
        if len(candidate_policies) != 1:
            blockers.append("SOURCE_NAT_REQUIRES_ONE_POLICY_ZONE_PAIR")

        group_identity = str(policy.policy_id if policy.policy_id is not None else f"unidentified-{order}")
        approval_group = item_key(vdom, "approval_group", f"source-nat:{group_identity}")
        fixed = plan_fixed_pool_nat(source, vdom, policy,
                    candidate_policies[0] if len(candidate_policies) == 1 else None, options, approval_group)
        if fixed is not None:
            pool_item, nat_item = fixed
            items.extend((pool_item, nat_item))
            links[candidate_policies[0].key] = (nat_item.key, approval_group)
            continue
        for pair_index, policy_item in enumerate(candidate_policies or [None]):
            identity = f"{group_identity}:{pair_index}:{policy_item.key if policy_item else 'unresolved'}"
            key = item_key(vdom, "source_nat", identity)
            policy_settings = dict(policy_item.settings) if policy_item else {}
            entry = entries[0] if len(entries) == 1 else None
            item_blockers = list(blockers)
            if policy_item:
                for earlier in policies:
                    earlier_settings = dict(earlier.settings)
                    if (earlier.source_order < policy_item.source_order
                            and earlier_settings.get("from_zone") == policy_settings.get("from_zone")
                            and earlier_settings.get("to_zone") == policy_settings.get("to_zone")
                            and not earlier_settings.get("disabled")
                            and earlier_settings.get("action") != "deny"):
                        item_blockers.append("SOURCE_NAT_EARLIER_POLICY_MAY_OVERLAP")
                        break
            if entry is not None and entry.translation_type == "interface_address":
                # The source model does not carry FortiOS port-preserve; do not infer a Junos profile.
                pass
            items.append(SRXPlanItem(
                key=key,
                family="source_nat",
                source_vdom=vdom,
                source_name=policy.name or str(policy.policy_id or f"policy-{order + 1}"),
                target_name=target_name("nat", vdom, identity),
                settings=(
                    ("policy_id", policy.policy_id),
                    ("source_policy_key", policy_item.key if policy_item else None),
                    ("from_zone", policy_settings.get("from_zone")),
                    ("to_zone", policy_settings.get("to_zone")),
                    ("translation_type", entry.translation_type if entry else None),
                    ("pool_names", entry.pool_names if entry else ()),
                    ("translated_addresses", entry.translated_addresses if entry else ()),
                    ("source_addresses", policy_settings.get("source_addresses", ())),
                    ("destination_addresses", policy_settings.get("destination_addresses", ())),
                    ("applications", policy_settings.get("applications", ())),
                    ("egress_interfaces", entry.egress_interfaces if entry else ()),
                ),
                dependencies=policy_item.dependencies if policy_item else (),
                blockers=tuple(dict.fromkeys(item_blockers)),
                source_order=policy_item.source_order if policy_item else order,
                approval_group=approval_group,
            ))
            if policy_item:
                links[policy_item.key] = (key, approval_group)
                if entry is not None and entry.translation_type == "interface_address":
                    policy_blockers[policy_item.key].append("POLICY_SOURCE_NAT_PORT_BEHAVIOR_UNVERIFIED")
                else:
                    policy_blockers[policy_item.key].append("POLICY_SOURCE_NAT_REQUIRES_SEPARATE_SUPPORT")

        for code in blockers:
            findings.append(SRXFinding(
                code,
                code.replace("_", " ").capitalize(),
                vdom,
                "source_nat",
                policy.name or str(policy.policy_id or "unknown"),
            ))

    vip_paths = {"firewall vip", "firewall vip6", "firewall vipgrp", "firewall vipgrp6"}
    vip_names = set()
    for record in source_inventory or ():
        if getattr(record, "vdom", None) != vdom:
            continue
        path = str(getattr(record, "source_path", "")).strip().lower()
        if path in _UNSUPPORTED_NAT_SECTIONS:
            name = getattr(record, "object_name", None)
            if path in vip_paths and name:
                vip_names.add(str(name))
            # Coverage is visible without blocking unrelated traffic.
            findings.append(SRXFinding(
                "FORTIGATE_NAT_SOURCE_EVIDENCE_REQUIRES_REVIEW",
                "FortiGate NAT source evidence is present and remains manual.",
                vdom,
                "source_nat",
                "FortiGate",
                blocking=False,
            ))

    if vip_names:
        for source_policy in (policy for policy in source.policies if policy.vdom == vdom):
            if not vip_names.intersection(source_policy.dstaddr or ()):
                continue
            for item in planned_by_policy_id.get(source_policy.policy_id, ()):
                policy_blockers[item.key].append("POLICY_DESTINATION_VIP_DNAT_UNSUPPORTED")
                findings.append(SRXFinding(
                    "POLICY_DESTINATION_VIP_DNAT_UNSUPPORTED",
                    "A policy references a FortiGate VIP whose destination translation is not supported.",
                    vdom,
                    "policy",
                    str(source_policy.policy_id or source_policy.name or "unknown"),
                ))

    return items, links, policy_blockers, list(dict.fromkeys(findings))


def attach_nat_review_groups(policies, nat_links, policy_blockers):
    result = []
    for item in policies:
        link = nat_links.get(item.key)
        if link is None:
            result.append(item)
            continue
        nat_key, approval_group = link
        result.append(replace(
            item,
            dependencies=tuple(dict.fromkeys((*item.dependencies, nat_key))),
            blockers=tuple(dict.fromkeys((*item.blockers, *policy_blockers[item.key]))),
            approval_group=approval_group,
        ))
    if policy_blockers:
        blocked_keys = set(policy_blockers)
        result = [replace(item, blockers=tuple(dict.fromkeys((*item.blockers, *policy_blockers[item.key]))))
                  if item.key in blocked_keys and item.key not in nat_links else item
                  for item in result]
    return result
