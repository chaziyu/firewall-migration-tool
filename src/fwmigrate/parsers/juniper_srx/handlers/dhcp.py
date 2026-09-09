"""Extract Junos DHCP hierarchy as source inventory."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperDHCPPool, JuniperDHCPRelayGroup
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_dhcp_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 3 or t[1].lower() not in {"access", "system"}:
        return False
    if t[1].lower() == "system" and t[2].lower() not in {"services", "service"}:
        return False
    if not any(x.lower() in {"dhcp-local-server", "address-assignment", "dhcp-relay"} for x in t):
        return False
    cmd.consumed, cmd.handler = True, "dhcp"
    lower = [x.lower() for x in t]
    if "dhcp-local-server" in lower:
        i = lower.index("group") if "group" in lower else -1
        if i >= 0 and i + 1 < len(t):
            cfg = context.dhcp_local_servers.setdefault(t[i + 1], [])
            if "interface" in lower and lower.index("interface") + 1 < len(t):
                cfg.append(t[lower.index("interface") + 1])
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    if "address-assignment" in [x.lower() for x in t]:
        i = next(i for i, x in enumerate(t) if x.lower() == "pool") if "pool" in [x.lower() for x in t] else -1
        if i >= 0 and i + 1 < len(t):
            pool = context.dhcp_pools.setdefault(t[i + 1], JuniperDHCPPool(name=t[i + 1]))
            rest = t[i + 2:]
            if len(rest) >= 2 and rest[0].lower() == "family":
                rest = rest[2:]
            if rest and rest[0].lower() in {"low", "high"} and len(rest) > 1:
                pool.ranges.append({rest[0].lower(): rest[1]})
            elif rest and rest[0].lower() == "router": pool.router.extend(extract_value_list(rest[1:]))
            elif rest and rest[0].lower() in {"name-server", "dns-server"}: pool.name_servers.extend(extract_value_list(rest[1:]))
            else: pool.source_attributes["_".join(sanitize_tokens(rest))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    elif "dhcp-relay" in [x.lower() for x in t]:
        i = next((i for i, x in enumerate(t) if x.lower() in {"group", "group-name"}), -1)
        if i >= 0 and i + 1 < len(t):
            group = context.dhcp_relays.setdefault(t[i + 1], JuniperDHCPRelayGroup(name=t[i + 1]))
            if "interface" in [x.lower() for x in t]: group.interfaces.append(t[-1])
            else: group.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
