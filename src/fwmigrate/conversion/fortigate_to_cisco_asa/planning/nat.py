"""Fail-closed NAT planning for features whose ordering and direction are not proven."""

from .naming import item_key
from ..models import ASAPlanItem


def plan_nat(source, derived, options, address_names, target_evidence=None):
    items = []
    vdom = options.source_vdom
    for nat in derived.nat:
        if nat.vdom != vdom:
            continue
        name = str(nat.policy_id if nat.policy_id is not None else nat.policy_name or "unknown")
        items.append(ASAPlanItem(item_key(vdom, "nat", name), "nat", vdom, name, "",
                                 blockers=("POLICY_NAT_ORDER_AND_TARGET_INTERACTIONS_UNVERIFIED",),
                                 source_order=int(nat.policy_id or 0)))
    for vip in source.vips:
        if (vip.vdom or "root") != vdom:
            continue
        items.append(ASAPlanItem(item_key(vdom, "vip", vip.name), "vip", vdom, vip.name, "",
                                 blockers=("STATIC_VIP_DIRECTION_AND_POLICY_SCOPE_UNVERIFIED",)))
    if source.vip_groups:
        items.append(ASAPlanItem(item_key(vdom, "vip_group", "all"), "vip_group", vdom,
                                 "VIP groups", "", blockers=("VIP_GROUP_NAT_EXPANSION_UNSUPPORTED",)))
    return items
