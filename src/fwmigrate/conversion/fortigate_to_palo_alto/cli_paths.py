"""PAN-OS CLI hierarchies for the FortiGate to PAN-OS migration pair."""


def address(item):
    return [("vsys", "address", item.target_name or item.source_name, item.address_type, item.value)]


def address_group(item):
    if item.members:
        return [("vsys", "address-group", item.target_name or item.source_name, "static", "[", *item.members, "]")]
    return []


def service(item):
    base = ("vsys", "service", item.target_name or item.source_name, "protocol", item.protocol)
    commands = [base]
    if item.destination_port:
        commands.append((*base, "port", item.destination_port))
    if item.source_port:
        commands.append((*base, "source-port", item.source_port))
    return commands


def service_group(item):
    if item.members:
        return [("vsys", "service-group", item.target_name or item.source_name, "members", "[", *item.members, "]")]
    return []


def schedule(item):
    name = item.target_name or item.source_name
    if item.schedule_type in {"weekly", "recurring"}:
        by_day = {}
        for day, start, end in item.weekly:
            by_day.setdefault(day, []).append(f"{start}-{end}")
        return [("vsys", "schedule", name, "schedule-type", "recurring")] + [
            ("vsys", "schedule", name, "schedule-type", "recurring", "weekly", day, "[", *ranges, "]")
            for day, ranges in by_day.items()
        ]
    if item.schedule_type == "daily":
        ranges = [f"{start}-{end}" for start, end in item.daily]
        return [("vsys", "schedule", name, "schedule-type", "recurring", "daily", "[", *ranges, "]")]
    if item.schedule_type in {"non-recurring", "one-time"}:
        ranges = [f"{start}-{end}" for start, end in item.non_recurring]
        return [("vsys", "schedule", name, "schedule-type", "non-recurring", "[", *ranges, "]")]
    return []


def zone(item):
    if item.interfaces:
        return [("vsys", "zone", item.target_name or item.source_name, "network", "layer3", "[", *item.interfaces, "]")]
    return []


def static_route(item):
    base = ("network", "virtual-router", item.virtual_router, "routing-table", "ip", "static-route", item.target_name or item.source_name)
    commands = [("device", *base, "destination", item.destination)]
    if item.interface:
        commands.append(("device", *base, "interface", item.interface))
    if item.nexthop_type == "discard":
        commands.append(("device", *base, "nexthop", "discard"))
    elif item.nexthop:
        commands.append(("device", *base, "nexthop", item.nexthop_type or "ip-address", item.nexthop))
    if item.admin_distance is not None:
        commands.append(("device", *base, "admin-dist", item.admin_distance))
    return commands


def security_rule(item):
    base = ("rulebase", "security", "rules", item.target_name or item.source_name)
    commands = [("vsys", *base, key, "[", *values, "]") for key, values in (("from", item.from_zones), ("to", item.to_zones), ("source", item.sources), ("destination", item.destinations), ("service", item.services))]
    if item.schedule: commands.append(("vsys", *base, "schedule", item.schedule))
    if item.negate_source: commands.append(("vsys", *base, "negate-source", "yes"))
    if item.negate_destination: commands.append(("vsys", *base, "negate-destination", "yes"))
    if item.disabled: commands.append(("vsys", *base, "disabled", "yes"))
    if item.description: commands.append(("vsys", *base, "description", item.description))
    if item.action: commands.append(("vsys", *base, "action", item.action))
    return commands


def nat_rule(item):
    base = ("rulebase", "nat", "rules", item.target_name or item.source_name)
    commands = [("vsys", *base, key, "[", *values, "]") for key, values in (("from", item.from_zones), ("to", item.to_zones), ("source", item.source_addresses), ("destination", item.destination_addresses)) if values]
    if item.service: commands.append(("vsys", *base, "service", item.service))
    if item.to_interface: commands.append(("vsys", *base, "to-interface", item.to_interface))
    if item.source_translation_type:
        path = (*base, "source-translation", item.source_translation_type)
        if item.source_interface_address: commands.append(("vsys", *path, "interface-address"))
        if item.translated_addresses:
            commands.append(("vsys", *path, "translated-address", "[", *item.translated_addresses, "]"))
    if item.destination_translated_address:
        commands.append(("vsys", *base, "destination-translation", "translated-address", item.destination_translated_address))
    if item.destination_translated_port:
        commands.append(("vsys", *base, "destination-translation", "translated-port", item.destination_translated_port))
    return commands
