"""Handler for Junos security zones configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperZone
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_zones_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set security zones security-zone <zone> ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 4:
        return False

    if toks[1].lower() != "security" or toks[2].lower() != "zones":
        return False

    if toks[3].lower() != "security-zone":
        return False

    if len(toks) < 5:
        return False

    zone_name = toks[4]
    cmd.consumed = True
    cmd.handler = "zones"

    if zone_name not in context.zones:
        context.zones[zone_name] = JuniperZone(name=zone_name)
    zone = context.zones[zone_name]

    if len(toks) == 5:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    sub = toks[5].lower()
    if sub == "description" and len(toks) >= 7:
        zone.description = toks[6]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif sub == "interfaces" and len(toks) >= 7:
        intf_list = extract_value_list(toks[6:])
        for intf in intf_list:
            if intf not in zone.interfaces:
                zone.interfaces.append(intf)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif sub == "screen" and len(toks) >= 7:
        zone.screen = toks[6]
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    elif sub == "tcp-rst":
        zone.tcp_rst = True
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    elif sub == "host-inbound-traffic" and len(toks) >= 7:
        hit_type = toks[6].lower()
        if hit_type == "system-services" and len(toks) >= 8:
            services = extract_value_list(toks[7:])
            for s in services:
                if s not in zone.host_inbound_system_services:
                    zone.host_inbound_system_services.append(s)
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True
        elif hit_type == "protocols" and len(toks) >= 8:
            protocols = extract_value_list(toks[7:])
            for p in protocols:
                if p not in zone.host_inbound_protocols:
                    zone.host_inbound_protocols.append(p)
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True

    # Other zone attributes
    attr_key = "_".join(toks[5:])
    zone.source_attributes[attr_key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
