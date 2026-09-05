"""Handler for Junos security zones configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperZone
from fwmigrate.parsers.juniper_srx.provenance import record_member_candidate, record_scalar_candidate
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_zones_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set security zones security-zone <zone> ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 3:
        return False

    if toks[1].lower() != "security" or toks[2].lower() != "zones":
        return False

    cmd.consumed = True
    cmd.handler = "zones"

    if len(toks) < 5 or toks[3].lower() != "security-zone":
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    zone_name = toks[4]
    if zone_name not in context.zones:
        context.zones[zone_name] = JuniperZone(name=zone_name)
    zone = context.zones[zone_name]

    if len(toks) == 5:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    sub = toks[5].lower()
    if sub == "description" and len(toks) >= 7:
        zone.description = toks[6]
        record_scalar_candidate(zone.field_provenance, zone.field_candidate_history, "description", zone.description, cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif sub == "interfaces" and len(toks) >= 9 and toks[7].lower() == "host-inbound-traffic":
        interface = toks[6]
        hit_type = toks[8].lower()
        target = zone.interface_host_inbound.setdefault(interface, {})
        if hit_type in {"system-services", "protocols"} and len(toks) > 9:
            key = "system_services" if hit_type == "system-services" else "protocols"
            values = extract_value_list(toks[9:])
            _record_members(zone, f"interface:{interface}:{key}", target.setdefault(key, []), values, cmd)
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True
    elif sub == "interfaces" and len(toks) >= 7 and "host-inbound-traffic" not in {t.lower() for t in toks[6:]}:
        intfs = extract_value_list(toks[6:])
        if context.context_type != "root" and any(i.lower() == "all" for i in intfs):
            zone.source_attributes.setdefault("invalid_children", []).append(
                sanitize_source_attributes({"path": toks[5:], "raw": cmd.raw_sanitized})
            )
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        for intf in intfs:
            record_member_candidate(zone.member_candidate_history, "interfaces", intf, cmd)
            if intf not in zone.interfaces:
                zone.interfaces.append(intf)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif sub == "screen" and len(toks) >= 7:
        zone.screen = toks[6]
        record_scalar_candidate(zone.field_provenance, zone.field_candidate_history, "screen", zone.screen, cmd)
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    elif sub == "tcp-rst":
        zone.tcp_rst = True
        record_scalar_candidate(zone.field_provenance, zone.field_candidate_history, "tcp-rst", True, cmd)
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    elif sub == "host-inbound-traffic" and len(toks) >= 7:
        interface = None
        offset = 6
        if toks[6].lower() == "interfaces" and len(toks) >= 8:
            interface = toks[7]
            offset = 8
        if len(toks) <= offset:
            return True
        hit_type = toks[offset].lower()
        target = zone.interface_host_inbound.setdefault(interface, {}) if interface else None
        if hit_type == "system-services" and len(toks) > offset + 1:
            services = extract_value_list(toks[offset + 1:])
            if target is not None:
                _record_members(zone, f"interface:{interface}:system_services", target.setdefault("system_services", []), services, cmd)
            else:
                _record_members(zone, "host_inbound_system_services", zone.host_inbound_system_services, services, cmd)
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True
        elif hit_type == "protocols" and len(toks) > offset + 1:
            protocols = extract_value_list(toks[offset + 1:])
            if target is not None:
                _record_members(zone, f"interface:{interface}:protocols", target.setdefault("protocols", []), protocols, cmd)
            else:
                _record_members(zone, "host_inbound_protocols", zone.host_inbound_protocols, protocols, cmd)
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True

    # Other zone attributes
    safe_toks = sanitize_tokens(toks)
    attr_key = "_".join(safe_toks[5:])
    zone.source_attributes[attr_key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _record_members(zone, field, target, values, cmd):
    for value in values:
        record_member_candidate(zone.member_candidate_history, field, value, cmd)
        if value not in target:
            target.append(value)
