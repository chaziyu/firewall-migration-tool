"""Verified static IPv4 VIP translation shared by address and NAT planning."""

from ipaddress import IPv4Address

from fwmigrate.vendors.fortigate.relationships.references import ReferenceIndex, ReferenceKind


def vip_port_translation(vip):
    if vip.portforward != 'enable' or vip.protocol not in {'tcp', 'udp'}:
        return None
    ports = (vip.extport, vip.mappedport)
    if not all(isinstance(port, str) and port.isdecimal() and 1 <= int(port) <= 65535 for port in ports):
        return None
    return vip.protocol, str(int(vip.extport)), str(int(vip.mappedport))


def vip_service_name(vip):
    return f'FG-VIP-{vip.name}-{vip.protocol}-{vip.extport}'


def vip_policy_consumers(source, derived):
    """Resolve scoped VIP consumers without treating invalid groups as partial matches."""
    index = getattr(derived, "references", None)
    if index is None:
        index = ReferenceIndex()
        for family, kind in (("vips", ReferenceKind.VIP), ("vip_groups", ReferenceKind.VIP_GROUP),
                             ("addresses", ReferenceKind.ADDRESS), ("address_groups", ReferenceKind.ADDRESS_GROUP)):
            for item in getattr(source, family, ()):
                if getattr(item, "address_family", "ipv4") == "ipv4":
                    index.add(kind, vdom=item.vdom or "root", name=item.name, target=item)
    consumers = {}
    kinds = (ReferenceKind.VIP, ReferenceKind.VIP_GROUP)
    duplicates = {(item.vdom, item.name) for item in index.duplicates if item.kind in kinds}
    for policy in getattr(source, "policies", ()):
        vdom = policy.vdom or "root"
        found, warnings, groups = {}, [], {}
        pending = [(name, ()) for name in policy.dstaddr or ()]
        visited = set()
        while pending:
            name, path = pending.pop()
            if name in path:
                warnings.append(f"circular VIP-group reference {name!r}")
                continue
            if (vdom, name) in duplicates or all(index.get(kind, vdom=vdom, name=name) is not None for kind in kinds):
                warnings.append(f"ambiguous VIP reference {name!r}")
            reference = index.resolve_any(vdom=vdom, name=name, kinds=kinds)
            if reference is None:
                if path:
                    warnings.append(f"unresolved VIP-group member {name!r} in VDOM {vdom!r}")
                continue
            if any(index.get(kind, vdom=vdom, name=name) is not None
                   for kind in (ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP)):
                warnings.append(f"ambiguous VIP/address reference {name!r}")
            if reference.kind is ReferenceKind.VIP:
                found.setdefault(name, set()).update(path)
                continue
            if path:
                warnings.append(f"nested VIP-group reference {name!r} is unsupported")
            if name in visited:
                continue
            visited.add(name)
            group = reference.target
            groups[name] = group
            if not group.members:
                warnings.append(f"VIP group {name!r} has no explicit members")
            for key in group.raw_extra:
                if key not in {"color"}:
                    warnings.append(f"unclassified VIP-group setting {key!r} requires manual review")
            pending.extend((member, (*path, name)) for member in group.members)
        for name in found:
            vip = index.get(ReferenceKind.VIP, vdom=vdom, name=name)
            group_warnings = [f"VIP-group interface {group.interface!r} is not verified for VIP {name!r}"
                              for group_name in found[name] if (group := groups[group_name]).interface not in {None, "any", vip.extintf}]
            consumers.setdefault((vdom, name), []).append((policy, tuple(dict.fromkeys([*warnings, *group_warnings]))))
    return consumers


def vip_translation(vip, derived=None):
    warnings = []
    ext = vip.extip
    mapped = vip.mappedip[0] if len(vip.mappedip) == 1 else None
    try:
        IPv4Address(ext)
        IPv4Address(mapped)
        if ext == "0.0.0.0" or mapped == "0.0.0.0":
            raise ValueError("interface-dependent VIP address")
    except (ValueError, TypeError):
        warnings.append("VIP requires one explicit external and mapped IPv4 host address")
    if vip.extaddr or vip.mapped_addr:
        warnings.append("VIP address-object translation requires manual resolution")
    from fwmigrate.vendors.fortigate.transform.effective_values import effective_value
    vip_type = vip.type if vip.type is not None else effective_value(derived, vip.vdom, 'vip', vip.name, 'type')
    if vip.realservers or vip.ldb_method or vip.service or vip_type != "static-nat":
        warnings.append("VIP type or load-balancing/service semantics are unsupported")
    if vip.status not in {None, "enable"}:
        warnings.append("VIP state is unsupported")
    for field in ("arp_reply", "server_type"):
        if getattr(vip, field, None) is not None:
            warnings.append(f"VIP {field} requires manual target semantics")
    for field in ("nat_source_vip", "monitor"):
        if getattr(vip, field, None) not in (None, [], "disable"):
            warnings.append(f"VIP {field} requires manual target semantics")
    for key in vip.raw_extra:
        warnings.append(f"unclassified VIP setting {key!r} requires manual review")
    if (vip.portforward not in {None, "disable", "no", "0"} or any(
        getattr(vip, field, None) for field in ("protocol", "extport", "mappedport")
    )) and vip_port_translation(vip) is None:
        warnings.append("VIP port-forwarding semantics are unsupported")
    return ext, mapped, warnings
