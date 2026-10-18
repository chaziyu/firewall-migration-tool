"""Restricted one-host, fixed-port source NAT with routed return traffic."""

from ipaddress import IPv4Address, IPv4Network

from ..models import SRXPlanItem
from .naming import item_key, target_name


NAT_POLICY_BLOCKERS = {
    "POLICY_NAT_REQUIRES_SEPARATE_SUPPORT",
    "POLICY_TRANSLATION_SETTINGS_UNSUPPORTED",
}


def plan_fixed_pool_nat(source, vdom, policy, candidate, options, approval_group):
    # shortcut: one host and one policy avoid unproven pool allocation and first-match interactions.
    if (
        options is None
        or not options.nat_return_routing_confirmed
        or len([row for row in source.policies if row.vdom == vdom]) != 1
        or any(row.vdom == vdom for row in source.central_snat)
        or any(
            row.vdom == vdom
            for family in ("vips", "vips6", "vip_groups", "vip_groups6")
            for row in getattr(source, family)
        )
        or candidate is None
        or set(candidate.blockers) - NAT_POLICY_BLOCKERS
        or policy.action != "accept"
        or policy.status != "enable"
        or policy.schedule != "always"
        or policy.nat != "enable"
        or policy.ippool != "enable"
        or len(policy.poolname or ()) != 1
        or policy.fixedport != "enable"
        or policy.port_preserve != "enable"
        or policy.natip is not None
        or policy.poolname6
        or policy.service != ["ALL"]
        or policy.dstaddr != ["all"]
        or len(policy.srcaddr or ()) != 1
        or any(
            row.vdom == vdom and row.name == "ALL"
            for row in (*source.services, *source.service_groups)
        )
        or any(
            row.vdom == vdom and row.name == "all"
            for row in (*source.addresses, *source.address_groups)
        )
        or any(
            getattr(policy, field) != "disable"
            for field in ("nat64", "nat46", "natinbound", "natoutbound")
        )
    ):
        return None
    hosts = [
        row
        for row in source.addresses
        if row.vdom == vdom and row.name == policy.srcaddr[0]
    ]
    pools = [
        row
        for row in source.ip_pools
        if row.vdom == vdom and row.name == policy.poolname[0]
    ]
    if len(hosts) != 1 or len(pools) != 1:
        return None
    host, pool = hosts[0], pools[0]
    if (
        host.type != "ipmask"
        or not {"type", "subnet"} <= host.explicit_fields
        or host.raw_extra
        or host.associated_interface
        or pool.type != "one-to-one"
        or pool.arp_reply != "disable"
        or pool.raw_extra
        or not {"type", "startip", "endip", "arp_reply"} <= pool.explicit_fields
        or pool.explicit_fields - {"type", "startip", "endip", "arp_reply", "comments"}
    ):
        return None
    try:
        parts = host.subnet.split()
        prefix = IPv4Network("/".join(parts), strict=True)
        address = IPv4Address(pool.startip)
        if (
            prefix.prefixlen != 32
            or address != IPv4Address(pool.endip)
            or address == prefix.network_address
        ):
            return None
    except (AttributeError, ValueError, TypeError):
        return None
    pool_name = target_name("nat", vdom, pool.name)
    pool_key = item_key(vdom, "source_nat_pool", pool.name)
    pool_item = SRXPlanItem(
        pool_key,
        "source_nat_pool",
        vdom,
        pool.name,
        pool_name,
        (("translated_address", str(address)),),
        approval_group=approval_group,
    )
    settings = dict(candidate.settings)
    settings.update(
        source_prefix=str(prefix),
        destination_prefix="0.0.0.0/0",
        pool_name=pool_name,
        source_policy_key=candidate.key,
    )
    nat = SRXPlanItem(
        item_key(vdom, "source_nat", str(policy.policy_id)),
        "source_nat",
        vdom,
        policy.name or str(policy.policy_id),
        target_name("nat", vdom, str(policy.policy_id)),
        tuple(settings.items()),
        (*candidate.dependencies, pool_key),
        source_order=candidate.source_order,
        approval_group=approval_group,
    )
    return pool_item, nat
