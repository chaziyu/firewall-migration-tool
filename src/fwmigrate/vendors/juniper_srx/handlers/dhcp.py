"""Extract Junos DHCP source hierarchies without merging distinct services."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.extraction import sanitize_tokens
from fwmigrate.vendors.juniper_srx.model import (
    JuniperAddressAssignmentFamily, JuniperAddressAssignmentPool,
    JuniperContextConfig, JuniperDHCPHostReservation,
    JuniperDHCPRange, JuniperDHCPRelayGroup, JuniperDHCPLocalServerGroup,
    JuniperRoutingInstance,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand, extract_value_list


def _key(routing_instance: str | None, name: str, family: str = "") -> str:
    return "|".join((routing_instance or "root", family, name))


def handle_dhcp_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    tokens = cmd.tokens
    if len(tokens) < 3:
        return False
    routing_instance = None
    if tokens[1].lower() == "routing-instances" and len(tokens) >= 5:
        routing_instance, tokens = tokens[2], tokens[3:]
        context.routing_instances.setdefault(routing_instance, JuniperRoutingInstance(name=routing_instance))
    elif tokens[1].lower() in {"system", "access"}:
        tokens = tokens[1:]
    else:
        return False

    lower = [token.lower() for token in tokens]
    if lower[:2] == ["system", "services"] and len(tokens) > 2:
        if lower[2] == "dhcp-local-server":
            return _local_server(cmd, context, tokens[3:], routing_instance)
        if lower[2] == "dhcp-relay":
            return _relay(cmd, context, tokens[3:], routing_instance)
        if lower[2] == "dhcp":
            context.dhcp.legacy.commands.append({"tokens": sanitize_tokens(cmd.tokens), "raw": cmd.raw_sanitized})
            cmd.consumed, cmd.handler = True, "dhcp"
            cmd.extraction_status = ExtractionStatus.SOURCE_ONLY
            return True
    if lower[:2] == ["access", "address-assignment"]:
        return _address_assignment(cmd, context, tokens[2:], routing_instance)
    return False


def _local_server(cmd: JunosCommand, context: JuniperContextConfig, tokens: list[str], routing_instance: str | None) -> bool:
    lower = [token.lower() for token in tokens]
    if "group" not in lower:
        context.dhcp.local_servers[_key(routing_instance, "__global__")] = JuniperDHCPLocalServerGroup(
            name="__global__", routing_instance=routing_instance,
            source_attributes={"raw": cmd.raw_sanitized},
        )
        status = ExtractionStatus.SOURCE_ONLY
    else:
        pos = lower.index("group")
        if pos + 1 >= len(tokens):
            return _consume_error(cmd, "missing DHCP local-server group name")
        name = tokens[pos + 1]
        family = "inet6" if "dhcpv6" in lower or "inet6" in lower else "inet" if "inet" in lower else None
        key = _key(routing_instance, name, family or "")
        group = context.dhcp.local_servers.setdefault(key, JuniperDHCPLocalServerGroup(
            name=name, routing_instance=routing_instance, family=family,
        ))
        if "interface" in lower and lower.index("interface") + 1 < len(tokens):
            interface = tokens[lower.index("interface") + 1]
            if interface not in group.interfaces:
                group.interfaces.append(interface)
            status = ExtractionStatus.EXTRACTED
        else:
            group.options["_".join(sanitize_tokens(tokens[pos + 2:]))] = cmd.raw_sanitized
            status = ExtractionStatus.PARTIAL
        group.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "dhcp", status
    return True


def _address_assignment(cmd: JunosCommand, context: JuniperContextConfig, tokens: list[str], routing_instance: str | None) -> bool:
    lower = [token.lower() for token in tokens]
    if "pool" not in lower or lower.index("pool") + 1 >= len(tokens):
        return _consume_source(cmd, context.dhcp.source_attributes)
    pos = lower.index("pool")
    name = tokens[pos + 1]
    rest = tokens[pos + 2:]
    rest_lower = [token.lower() for token in rest]
    family_name = "inet6" if "inet6" in rest_lower else "inet" if "inet" in rest_lower else None
    pool_key = _key(routing_instance, name)
    pool = context.dhcp.address_assignment_pools.setdefault(pool_key, JuniperAddressAssignmentPool(
        name=name, routing_instance=routing_instance,
    ))
    if len(rest) >= 2 and rest[0].lower() == "link":
        pool.linked_pool = rest[1]
        cmd.consumed, cmd.handler, cmd.extraction_status = True, "dhcp", ExtractionStatus.EXTRACTED
        return True
    if family_name is None:
        pool.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
        cmd.consumed, cmd.handler, cmd.extraction_status = True, "dhcp", ExtractionStatus.SOURCE_ONLY
        return True
    family = pool.families.setdefault(family_name, JuniperAddressAssignmentFamily(name=family_name))
    recognized = False

    if "range" in rest_lower:
        i = rest_lower.index("range")
        if i + 1 < len(rest):
            range_name = rest[i + 1]
            item = family.ranges.setdefault(range_name, JuniperDHCPRange(name=range_name))
            tail = rest[i + 2:]
            for field in ("low", "high"):
                if field in [token.lower() for token in tail]:
                    value_pos = [token.lower() for token in tail].index(field) + 1
                    if value_pos < len(tail):
                        setattr(item, field, tail[value_pos])
                        recognized = True
            item.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    elif "host" in rest_lower:
        i = rest_lower.index("host")
        if i + 1 < len(rest):
            host_name = rest[i + 1]
            host = family.hosts.setdefault(host_name, JuniperDHCPHostReservation(name=host_name))
            for field, attr in (("hardware-address", "hardware_address"), ("ip-address", "ip_address")):
                if field in rest_lower and rest_lower.index(field) + 1 < len(rest):
                    setattr(host, attr, rest[rest_lower.index(field) + 1])
            host.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
            recognized = True
    elif "dhcp-attributes" in rest_lower:
        i = rest_lower.index("dhcp-attributes")
        attrs = rest[i + 1:]
        if attrs:
            key = attrs[0].lower()
            values = extract_value_list(attrs[1:])
            if key == "router":
                family.dhcp_attributes.router.extend(v for v in values if v not in family.dhcp_attributes.router)
                recognized = True
            elif key in {"name-server", "dns-server"}:
                family.dhcp_attributes.name_servers.extend(v for v in values if v not in family.dhcp_attributes.name_servers)
                recognized = True
            elif key in {"maximum-lease-time", "lease-time"} and values:
                family.dhcp_attributes.lease_time = values[0]
                recognized = True
            else:
                family.dhcp_attributes.source_attributes["_".join(sanitize_tokens(attrs))] = cmd.raw_sanitized
    if not recognized:
        pool.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    cmd.consumed, cmd.handler = True, "dhcp"
    cmd.extraction_status = ExtractionStatus.EXTRACTED if recognized else ExtractionStatus.SOURCE_ONLY
    return True


def _relay(cmd: JunosCommand, context: JuniperContextConfig, tokens: list[str], routing_instance: str | None) -> bool:
    lower = [token.lower() for token in tokens]
    if "group" in lower and lower.index("group") + 1 < len(tokens):
        name = tokens[lower.index("group") + 1]
    elif "group-name" in lower and lower.index("group-name") + 1 < len(tokens):
        name = tokens[lower.index("group-name") + 1]
    else:
        return _consume_source(cmd, context.dhcp.source_attributes)
    key = _key(routing_instance, name)
    group = context.dhcp.relay_groups.setdefault(key, JuniperDHCPRelayGroup(name=name, routing_instance=routing_instance))
    if "interface" in lower and lower.index("interface") + 1 < len(tokens):
        value = tokens[lower.index("interface") + 1]
        if value not in group.interfaces:
            group.interfaces.append(value)
    elif "active-server-group" in lower and lower.index("active-server-group") + 1 < len(tokens):
        value = tokens[lower.index("active-server-group") + 1]
        if value not in group.server_groups:
            group.server_groups.append(value)
    else:
        group.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    cmd.consumed, cmd.handler = True, "dhcp"
    cmd.extraction_status = ExtractionStatus.EXTRACTED if "interface" in lower or "active-server-group" in lower else ExtractionStatus.SOURCE_ONLY
    return True


def _consume_source(cmd: JunosCommand, target: dict) -> bool:
    target.setdefault("commands", []).append(cmd.raw_sanitized)
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "dhcp", ExtractionStatus.SOURCE_ONLY
    return True


def _consume_error(cmd: JunosCommand, reason: str) -> bool:
    cmd.consumed, cmd.handler, cmd.parse_error = True, "dhcp", reason
    cmd.extraction_status = ExtractionStatus.PARSE_ERROR
    return True
