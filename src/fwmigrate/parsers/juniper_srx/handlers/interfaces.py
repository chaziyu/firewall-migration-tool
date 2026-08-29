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

    # Check top-level interface settings: description, disable
    third = toks[3].lower()
    if third == "description" and len(toks) >= 5:
        intf.description = toks[4]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif third == "disable":
        intf.disabled = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
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
        elif sub == "family" and len(toks) >= 8:
            family_type = toks[6].lower()  # inet or inet6
            if toks[7].lower() == "address" and len(toks) >= 9:
                addr_val = toks[8]
                is_primary = False
                is_pref = False
                for extra in toks[9:]:
                    if extra.lower() == "primary":
                        is_primary = True
                    elif extra.lower() == "preferred":
                        is_pref = True

                unit.addresses.append(
                    JuniperInterfaceAddress(
                        family=family_type,
                        address=addr_val,
                        primary=is_primary,
                        preferred=is_pref,
                    )
                )
                cmd.extraction_status = ExtractionStatus.NORMALIZED
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
