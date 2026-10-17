"""Explicit Layer 3 interface, zone and static-route placement."""
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from .context import unsupported_fields
from .source_scope import identity, in_scope
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def plan_interfaces(ctx):
    result = []
    requirements = set(ctx.options.interfaces)
    for obj in (*ctx.source.interfaces, *ctx.source.interface_units):
        if obj.name not in requirements or not obj.scope or obj.scope.device_name != ctx.scope.device_name:
            continue
        target = ctx.options.interfaces[obj.name]
        reasons = unsupported_fields(obj, {"mode", "interface_family", "ipv4_addresses", "parent", "tag", "comment"})
        topology = [t for t in ctx.derived.interface_topology if t.interface == obj.name and t.scope == pan_scope_identity(obj.scope)]
        if len(topology) != 1 or topology[0].issues or len(topology[0].imported_vsys) != 1 or ctx.scope.name not in topology[0].imported_vsys:
            reasons.append("Interface ownership/topology is incomplete or ambiguous.")
        parent = getattr(obj, "parent", None)
        settings, dependencies = {"vdom": ctx.options.vdom}, []
        if obj.interface_family != "ethernet" or (not parent and obj.mode != "layer3"):
            reasons.append("Only Layer 3 ethernet interfaces and VLAN units are supported.")
        if parent:
            parents = [p for p in ctx.source.interfaces if p.name == parent and p.scope == obj.scope]
            if len(parents) != 1 or parent not in ctx.options.interfaces or not str(obj.tag or "").isdigit() or not 1 <= int(obj.tag) <= 4094:
                reasons.append("Explicit VLAN parent mapping and tag are required.")
            else:
                dependencies.append(identity(parents[0], "interface"))
                settings.update({"interface": ctx.options.interfaces[parent], "vlanid": obj.tag})
        elif target not in ctx.options.profile.get("ports", []):
            reasons.append("Physical interface must be in the explicitly declared destination port inventory.")
        if obj.ipv4_addresses is None or len(obj.ipv4_addresses) != 1:
            reasons.append("Exactly one explicit primary IPv4 address is required.")
        else:
            try:
                ip = IPv4Interface(obj.ipv4_addresses[0])
                settings["ip"] = (str(ip.ip), str(ip.netmask))
            except ValueError:
                reasons.append("Invalid primary IPv4 interface address.")
        if ctx.options.profile.get("vdom_mode") == "single":
            settings.pop("vdom")
        result.append(ctx.item(obj, "interface", "system interface", settings, dependencies, reasons,
                               target_name=target, disposition="CREATE" if parent else "CONFIGURE", global_scope=True))
    return result


def plan_zones(ctx, interfaces):
    result = []
    for obj in ctx.source.zones:
        if not in_scope(obj, ctx.scope):
            continue
        reasons = unsupported_fields(obj, {"network_type", "members"})
        deps, members = [], []
        if obj.network_type != "layer3" or not obj.members:
            reasons.append("Only nonempty Layer 3 zones are supported.")
        for member in obj.members or ():
            matches = [i for i in interfaces if i.source_name == member]
            if len(matches) != 1:
                reasons.append("Every zone member requires an explicit unique interface mapping.")
            else:
                deps.append(matches[0].key)
                members.append(matches[0].target_name)
        target = ctx.options.zones.get(obj.name)
        if not target:
            reasons.append("Choose a target zone.")
        # Explicit deny prevents accidental FortiGate intra-zone access; defaults are reviewed separately.
        result.append(ctx.item(obj, "zone", "system zone", {"interface": members, "intrazone": "deny"}, deps, reasons,
                               target_name=target or ctx.name(obj)))
    return result


def plan_routes(ctx, interfaces):
    result = []
    routers = [r for r in ctx.source.virtual_routers if r.scope and r.scope.device_name == ctx.scope.device_name]
    for router in routers:
        if not any(i.source_name in (router.interfaces or ()) for i in interfaces):
            continue
        for number, obj in enumerate(router.static_routes or (), 1):
            reasons = unsupported_fields(obj, {"destination", "nexthop", "nexthop_type", "nexthop_ip_address", "interface", "admin_distance", "router_name", "router_type", "address_family"})
            settings, deps = {}, []
            vrf = ctx.options.routers.get(router.name)
            matches = [i for i in interfaces if i.source_name == obj.interface]
            if vrf != 0:
                reasons.append("Initial static-route support requires an explicit VRF 0 mapping; routing-domain merging is prohibited.")
            if len(routers) != 1:
                reasons.append("Multiple source routing domains require manual isolation design.")
            if len(matches) != 1:
                reasons.append("Route requires a mapped outgoing interface.")
            else:
                settings["device"] = matches[0].target_name
                deps.append(matches[0].key)
            try:
                net = IPv4Network(obj.destination, strict=False)
                if obj.nexthop_type != "ip-address" or obj.admin_distance is None or not 1 <= int(obj.admin_distance) <= 255:
                    raise ValueError
                settings.update({"dst": (str(net.network_address), str(net.netmask)), "gateway": str(IPv4Address(obj.nexthop_ip_address)),
                                 "distance": obj.admin_distance})
            except (ValueError, TypeError):
                reasons.append("Route needs explicit supported IPv4 next hop, prefix and administrative distance.")
            result.append(ctx.item(obj, "static_route", "router static", settings, deps, reasons, target_name=str(number)))
    return result
