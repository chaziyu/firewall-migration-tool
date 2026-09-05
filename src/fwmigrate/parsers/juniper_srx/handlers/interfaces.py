"""Handler for Junos interfaces configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig,
    JuniperInterface,
    JuniperInterfaceAddress,
    JuniperInterfaceUnit,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_interfaces_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set interfaces <intf> ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "interfaces":
        return False

    intf_name = toks[2]
    cmd.consumed = True
    cmd.handler = "interfaces"

    if intf_name not in context.interfaces:
        context.interfaces[intf_name] = JuniperInterface(name=intf_name)
    intf = context.interfaces[intf_name]

    if len(toks) == 3:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    # Physical-interface settings. Values remain optional: Junos has no safe
    # parser default for omitted operational configuration.
    third = toks[3].lower()
    if third == "description" and len(toks) >= 5:
        intf.description = toks[4]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif third == "disable":
        intf.disabled = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif third in {"mtu", "speed", "link-mode", "encapsulation"} and len(toks) >= 5:
        value = toks[4]
        if third == "mtu":
            try:
                intf.mtu = int(value)
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.parse_error = f"Invalid mtu: {value}"
                return True
        elif third == "speed":
            intf.speed = value
        elif third == "link-mode":
            intf.link_mode = value
        else:
            intf.encapsulation = value
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif third in {"gigether-options", "ether-options", "fastether-options"}:
        _store_source(intf.physical_link, toks[3:], cmd)
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # Unit level settings: set interfaces <intf> unit <unit> ...
    if third == "unit" and len(toks) >= 5:
        unit_num = toks[4]
        if unit_num not in intf.units:
            intf.units[unit_num] = JuniperInterfaceUnit(unit=unit_num)
        unit = intf.units[unit_num]

        if len(toks) == 5:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[5].lower()
        if sub == "description" and len(toks) >= 7:
            unit.description = toks[6]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "disable":
            unit.disabled = True
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "vlan-id" and len(toks) >= 7:
            try:
                unit.vlan_id = int(toks[6])
                cmd.extraction_status = ExtractionStatus.NORMALIZED
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.parse_error = f"Invalid vlan-id: {toks[6]}"
            return True
        elif sub == "encapsulation" and len(toks) >= 7:
            unit.encapsulation = toks[6]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "family" and len(toks) >= 8:
            return _handle_family(toks[6:], unit, cmd)
        elif sub == "vrrp-group" and len(toks) >= 8:
            entry = {"group": toks[6], toks[7].lower(): toks[8:] or True}
            unit.vrrp.append(sanitize_source_attributes(entry))
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True
        elif sub == "filter" and len(toks) >= 8:
            unit.filters.append(sanitize_source_attributes({"direction": toks[6], "name": toks[7]}))
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True

        # Other unit attributes
        safe_toks = sanitize_tokens(toks)
        unit_key = "_".join(safe_toks[5:])
        unit.source_attributes[unit_key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # Other interface attributes
    safe_toks = sanitize_tokens(toks)
    intf_key = "_".join(safe_toks[3:])
    intf.source_attributes[intf_key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _store_source(target: dict, tokens: list[str], cmd: JunosCommand) -> None:
    key = "_".join(sanitize_tokens(tokens))
    target[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})


def _handle_family(tokens: list[str], unit: JuniperInterfaceUnit, cmd: JunosCommand) -> bool:
    family = tokens[0].lower()
    child = tokens[1].lower() if len(tokens) > 1 else ""
    if child == "address" and len(tokens) >= 3:
        extras = {t.lower() for t in tokens[3:]}
        unit.addresses.append(JuniperInterfaceAddress(
            family=family,
            address=tokens[2],
            primary="primary" in extras,
            preferred="preferred" in extras,
        ))
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    if child == "filter" and len(tokens) >= 4:
        unit.filters.append(sanitize_source_attributes({
            "family": family, "direction": tokens[2], "name": tokens[3],
        }))
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    _store_source(unit.family_attributes.setdefault(family, {}), tokens[1:], cmd)
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
