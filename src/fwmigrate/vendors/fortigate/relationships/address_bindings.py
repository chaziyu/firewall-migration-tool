"""Source-only proof that address interface restrictions hold for policy consumers."""


def association_verified(address, config):
    binding = address.associated_interface
    vdom = address.vdom or "root"
    if config is None or sum((item.vdom or "root") == vdom and item.name == binding for item in config.interfaces) != 1:
        return False
    groups = {}
    for item in config.address_groups:
        if item.address_family == "ipv4" and (item.vdom or "root") == vdom:
            groups.setdefault(item.name, []).append(item)

    def contains(names, seen=()):
        if address.name in names:
            return True
        for name in names:
            if name in seen or len(seen) >= 64:
                return None
            matches = groups.get(name, ())
            if len(matches) > 1:
                return None
            if matches:
                found = contains(matches[0].members or (), (*seen, name))
                if found is not False:
                    return found
        return False

    for policy in config.policies:
        if (policy.vdom or "root") != vdom:
            continue
        for names, interfaces in ((policy.srcaddr or (), policy.srcintf), (policy.dstaddr or (), policy.dstintf)):
            found = contains(names)
            if found is None or found and set(interfaces or ()) != {binding}:
                return False
    return True
