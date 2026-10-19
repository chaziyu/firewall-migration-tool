"""One-host fixed-port source translation on an explicitly empty NAT baseline."""

from ipaddress import IPv4Address, IPv4Network

from ..models import ASAPlanItem
from .naming import item_key, target_name


def plan_fixed_pool_nat(source, options, address_names, evidence):
    vdom = options.source_vdom
    policies = [row for row in source.policies if row.vdom == vdom]
    if any(row.vdom == vdom and row.type not in {"physical", "ethernet"} for row in source.interfaces):
        return None
    if (
        len(policies) != 1
        or evidence is None
        or not {"nat", "access_rules", "acl_bindings", "objects"}
        <= set(evidence["complete_families"])
        or evidence["config"].nat_rules
        or evidence["config"].access_rules
        or evidence["config"].acl_bindings
        or evidence["config"].vpn_address_pools
        or evidence["config"].service_policies
        or evidence["config"].traffic_zones
        or evidence["config"].connection_controls
        or any(row.vdom == vdom for row in source.central_snat)
        or any(
            row.vdom == vdom
            for family in ("vips", "vips6", "vip_groups", "vip_groups6")
            for row in getattr(source, family)
        )
    ):
        return None
    mappings = options.interfaces.get(vdom, {})
    physical_names = [row.interface.casefold() for row in mappings.values()]
    nameifs = [row.nameif.casefold() for row in mappings.values()]
    if (
        len(physical_names) != len(set(physical_names))
        or len(nameifs) != len(set(nameifs))
        or set(mappings) != {row.name for row in source.interfaces if row.vdom == vdom}
        or any(
            row.name.casefold() not in physical_names
            for row in evidence["config"].interfaces
        )
    ):
        return None
    policy = policies[0]
    name = str(policy.policy_id)
    key = item_key(vdom, "nat", name)
    if (
        policy.policy_id is None
        or options.nat_evidence.get(key, {}).get("return_routing_confirmed") is not True
        or policy.status != "enable"
        or policy.action != "accept"
        or policy.schedule != "always"
        or policy.nat != "enable"
        or policy.ippool != "enable"
        or len(policy.poolname or ()) != 1
        or policy.fixedport != "enable"
        or policy.port_preserve != "enable"
        or policy.utm_status != "disable"
        or policy.dstintf != ["any"]
        or len(policy.srcintf or ()) != 1
        or len(policy.dstaddr or ()) != 1
        or len(policy.service or ()) != 1
        or len(policy.srcaddr or ()) != 1
        or policy.natip is not None
        or policy.poolname6
        or any(
            getattr(policy, field) != "disable"
            for field in ("nat64", "nat46", "natinbound", "natoutbound")
        )
        or any(
            row.vdom == vdom and row.name == "all"
            for row in (*source.addresses, *source.address_groups)
        )
        or any(
            row.vdom == vdom and row.name == "ALL"
            for row in (*source.services, *source.service_groups)
        )
    ):
        return None
    interfaces = [
        row
        for row in source.interfaces
        if row.vdom == vdom and row.name == policy.srcintf[0]
    ]
    hosts = [
        row
        for row in source.addresses
        if row.vdom == vdom and row.name == policy.srcaddr[0]
    ]
    destinations = [
        row
        for row in source.addresses
        if row.vdom == vdom and row.name == policy.dstaddr[0]
    ]
    services = [
        row
        for row in source.services
        if row.vdom == vdom and row.name == policy.service[0]
    ]
    pools = [
        row
        for row in source.ip_pools
        if row.vdom == vdom and row.name == policy.poolname[0]
    ]
    mapping = options.interfaces.get(vdom, {}).get(policy.srcintf[0])
    if (
        len(interfaces) != 1
        or len(hosts) != 1
        or len(pools) != 1
        or mapping is None
        or len(destinations) != 1
        or len(services) != 1
    ):
        return None
    host, pool = hosts[0], pools[0]
    destination, service = destinations[0], services[0]
    if (
        destination.type != "ipmask"
        or destination.raw_extra
        or destination.associated_interface
        or not {"type", "subnet"} <= destination.explicit_fields
        or service.tcp_portrange != "443"
        or "tcp_portrange" not in service.explicit_fields
        or service.udp_portrange
        or service.sctp_portrange
        or service.raw_extra
    ):
        return None
    if (
        host.name not in address_names
        or host.type != "ipmask"
        or host.raw_extra
        or host.associated_interface
        or not {"type", "subnet"} <= host.explicit_fields
        or pool.type != "one-to-one"
        or pool.arp_reply != "disable"
        or pool.raw_extra
        or not {"type", "startip", "endip", "arp_reply"} <= pool.explicit_fields
        or pool.explicit_fields - {"type", "startip", "endip", "arp_reply", "comments"}
    ):
        return None
    try:
        prefix = IPv4Network("/".join(host.subnet.split()), strict=True)
        destination_prefix = IPv4Network(
            "/".join(destination.subnet.split()), strict=True
        )
        address = IPv4Address(pool.startip)
        if (
            prefix.prefixlen != 32
            or destination_prefix.prefixlen != 32
            or address != IPv4Address(pool.endip)
            or address == prefix.network_address
            or destination_prefix.network_address in {address, prefix.network_address}
            or any(row.ip == str(address) for row in evidence["config"].interfaces)
        ):
            return None
    except (AttributeError, ValueError, TypeError):
        return None
    group = item_key(vdom, "approval_group", "nat:" + name)
    mapped_name = target_name("nat", vdom, pool.name)
    mapped_key = item_key(vdom, "nat_pool", pool.name)
    mapped = ASAPlanItem(
        mapped_key,
        "nat_pool",
        vdom,
        pool.name,
        mapped_name,
        (("commands", (f"object network {mapped_name}", f" host {address}")),),
        approval_group=group,
    )
    # Reverse initiation is denied by the atomic ACL bindings on every ingress interface.
    command = f"nat ({mapping.nameif},any) source static {address_names[host.name]} {mapped_name} no-proxy-arp"
    nat = ASAPlanItem(
        key,
        "nat",
        vdom,
        name,
        "",
        (("commands", (command,)),),
        (
            item_key(vdom, "address", host.name),
            item_key(vdom, "interface", interfaces[0].name),
            mapped_key,
        ),
        approval_group=group,
    )
    return mapped, nat
