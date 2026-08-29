"""Handler for Junos security policies (zone-pair and global policies) configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperPolicy
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_policies_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle security policies commands across:
    1. Zone-pair policies: 'set security policies from-zone <from> to-zone <to> policy <name> ...'
    2. Global policies: 'set security policies global policy <name> ...'
    """
    toks = cmd.tokens
    if len(toks) < 3:
        return False

    if toks[1].lower() != "security" or toks[2].lower() != "policies":
        return False

    cmd.consumed = True
    cmd.handler = "policies"

    if len(toks) < 4:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    # Case 2: Global policy
    if toks[3].lower() == "global" and len(toks) >= 6 and toks[4].lower() == "policy":
        pol_name = toks[5]
        pol = _get_or_create_global_policy(context, pol_name)
        if len(toks) == 6:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        return _parse_policy_body(cmd, toks[6:], pol)

    # Case 1: Zone-pair policy
    # set security policies from-zone <fz> to-zone <tz> policy <name> ...
    if (
        len(toks) >= 8
        and toks[3].lower() == "from-zone"
        and toks[5].lower() == "to-zone"
        and toks[7].lower() == "policy"
    ):
        from_z = toks[4]
        to_z = toks[6]
        pol_name = toks[8]
        pol = _get_or_create_zone_policy(context, pol_name, from_z, to_z)
        if len(toks) == 9:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        return _parse_policy_body(cmd, toks[9:], pol)

    # Unknown policy hierarchy
    cmd.extraction_status = ExtractionStatus.UNSUPPORTED
    cmd.requires_manual_review = True
    return True


def _get_or_create_zone_policy(
    context: JuniperContextConfig, name: str, from_zone: str, to_zone: str
) -> JuniperPolicy:
    for p in context.policies:
        if p.name == name and p.from_zones == [from_zone] and p.to_zones == [to_zone]:
            return p
    pol = JuniperPolicy(
        name=name,
        policy_scope="zone",
        from_zones=[from_zone],
        to_zones=[to_zone],
    )
    context.policies.append(pol)
    return pol


def _get_or_create_global_policy(context: JuniperContextConfig, name: str) -> JuniperPolicy:
    for p in context.global_policies:
        if p.name == name:
            return p
    pol = JuniperPolicy(name=name, policy_scope="global")
    context.global_policies.append(pol)
    return pol


def _parse_policy_body(cmd: JunosCommand, body_toks: list[str], pol: JuniperPolicy) -> bool:
    if not body_toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    key = body_toks[0].lower()

    if key == "description" and len(body_toks) >= 2:
        pol.description = body_toks[1]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "scheduler-name" and len(body_toks) >= 2:
        pol.scheduler_name = body_toks[1]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    # Match criteria: match ...
    if key == "match" and len(body_toks) >= 2:
        match_key = body_toks[1].lower()

        if match_key == "source-address" and len(body_toks) >= 3:
            addrs = extract_value_list(body_toks[2:])
            for a in addrs:
                if a not in pol.source_addresses:
                    pol.source_addresses.append(a)
            if "source-address" not in pol.parsed_match_fields:
                pol.parsed_match_fields.append("source-address")
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-address" and len(body_toks) >= 3:
            addrs = extract_value_list(body_toks[2:])
            for a in addrs:
                if a not in pol.destination_addresses:
                    pol.destination_addresses.append(a)
            if "destination-address" not in pol.parsed_match_fields:
                pol.parsed_match_fields.append("destination-address")
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "application" and len(body_toks) >= 3:
            apps = extract_value_list(body_toks[2:])
            for a in apps:
                if a not in pol.applications:
                    pol.applications.append(a)
            if "application" not in pol.parsed_match_fields:
                pol.parsed_match_fields.append("application")
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "source-address-excluded":
            pol.source_address_excluded = True
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_key == "destination-address-excluded":
            pol.destination_address_excluded = True
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_key == "from-zone" and len(body_toks) >= 3:
            zones = extract_value_list(body_toks[2:])
            for z in zones:
                if z not in pol.from_zones:
                    pol.from_zones.append(z)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "to-zone" and len(body_toks) >= 3:
            zones = extract_value_list(body_toks[2:])
            for z in zones:
                if z not in pol.to_zones:
                    pol.to_zones.append(z)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "dynamic-application" and len(body_toks) >= 3:
            apps = extract_value_list(body_toks[2:])
            for a in apps:
                if a not in pol.dynamic_applications:
                    pol.dynamic_applications.append(a)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_key == "source-identity" and len(body_toks) >= 3:
            ids = extract_value_list(body_toks[2:])
            for i in ids:
                if i not in pol.source_identities:
                    pol.source_identities.append(i)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_key == "source-end-user-profile" and len(body_toks) >= 3:
            profiles = extract_value_list(body_toks[2:])
            for p in profiles:
                if p not in pol.source_end_user_profiles:
                    pol.source_end_user_profiles.append(p)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True

        # Unknown match condition
        pol.unknown_match_conditions["_".join(body_toks[1:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    # Action: then ...
    if key == "then" and len(body_toks) >= 2:
        then_act = body_toks[1].lower()
        if then_act in ("permit", "deny", "reject"):
            pol.action = then_act
            if len(body_toks) > 2:
                # permit sub-options
                pol.permit_options["_".join(body_toks[2:])] = sanitize_source_attributes(
                    {"raw": cmd.raw_sanitized}
                )
            cmd.extraction_status = (
                ExtractionStatus.NORMALIZED
                if then_act in ("permit", "deny")
                else ExtractionStatus.PARTIALLY_NORMALIZED
            )
            if then_act == "reject":
                cmd.requires_manual_review = True
            return True
        elif then_act == "log" and len(body_toks) >= 3:
            log_type = body_toks[2].lower()
            if log_type == "session-init":
                pol.log_session_init = True
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif log_type == "session-close":
                pol.log_session_close = True
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
        elif then_act == "count":
            pol.count = True
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        pol.unknown_then_options["_".join(body_toks[1:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    pol.source_attributes["_".join(body_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
