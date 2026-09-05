"""Handler for Junos security policies (zone-pair and global policies) configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
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

    first = toks[1].lower()
    second = toks[2].lower()

    if first != "security" or second != "policies":
        return False

    cmd.consumed = True
    cmd.handler = "policies"

    # 1. Global policies: set security policies global policy <name> ...
    if len(toks) >= 6 and toks[3].lower() == "global" and toks[4].lower() == "policy":
        pol_name = toks[5]
        pol = _get_or_create_policy(context.global_policies, pol_name, "global", None, None)
        if len(toks) == 6:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        return _parse_policy_body(cmd, toks[6:], pol)

    # 2. Zone-pair policies: set security policies from-zone <from> to-zone <to> policy <name> ...
    if (
        len(toks) >= 8
        and toks[3].lower() == "from-zone"
        and toks[5].lower() == "to-zone"
        and toks[7].lower() == "policy"
    ):
        from_z = toks[4]
        to_z = toks[6]
        pol_name = toks[8]
        pol = _get_or_create_policy(context.policies, pol_name, "zone", from_z, to_z)
        if from_z not in pol.from_zones:
            pol.from_zones.append(from_z)
        if to_z not in pol.to_zones:
            pol.to_zones.append(to_z)

        if len(toks) == 9:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        return _parse_policy_body(cmd, toks[9:], pol)

    # Deactivation / unparsed security policies level commands
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _get_or_create_policy(pol_list, name, scope="zone", from_zone=None, to_zone=None):
    key = "|".join((scope, from_zone or "", to_zone or "", name))
    for p in pol_list:
        if p.policy_key == key:
            return p
    new_p = JuniperPolicy(name=name, policy_scope=scope, from_zone=from_zone, to_zone=to_zone, policy_key=key)
    if from_zone:
        new_p.from_zones.append(from_zone)
    if to_zone:
        new_p.to_zones.append(to_zone)
    pol_list.append(new_p)
    return new_p


def _parse_policy_body(
    cmd: JunosCommand, body_toks: list[str], pol: JuniperPolicy
) -> bool:
    if not body_toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    key = body_toks[0].lower()

    if key == "description" and len(body_toks) >= 2:
        pol.description = " ".join(body_toks[1:])
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "scheduler-name" and len(body_toks) >= 2:
        pol.scheduler_name = body_toks[1]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "application-services" and len(body_toks) >= 2:
        pol.application_services.extend(v for v in extract_value_list(body_toks[1:]) if v not in pol.application_services)
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    # Match criteria: match ...
    if key == "match" and len(body_toks) >= 2:
        match_type = body_toks[1].lower()
        vals = extract_value_list(body_toks[2:]) if len(body_toks) > 2 else []

        if match_type == "source-address":
            for v in vals:
                if v not in pol.source_addresses:
                    pol.source_addresses.append(v)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_type == "source-address-excluded":
            pol.source_address_excluded = True
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_type == "destination-address":
            for v in vals:
                if v not in pol.destination_addresses:
                    pol.destination_addresses.append(v)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_type == "destination-address-excluded":
            pol.destination_address_excluded = True
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_type == "application":
            for v in vals:
                if v not in pol.applications:
                    pol.applications.append(v)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_type == "dynamic-application":
            for v in vals:
                if v not in pol.dynamic_applications:
                    pol.dynamic_applications.append(v)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif match_type == "from-zone":
            for v in vals:
                if v not in pol.from_zones:
                    pol.from_zones.append(v)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_type == "to-zone":
            for v in vals:
                if v not in pol.to_zones:
                    pol.to_zones.append(v)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_type == "source-identity":
            for v in vals:
                if v not in pol.source_identities:
                    pol.source_identities.append(v)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True

        # Unknown match condition
        safe_body_toks = sanitize_tokens(body_toks)
        pol.unknown_match_conditions["_".join(safe_body_toks[1:])] = sanitize_source_attributes(
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
            if then_act == "permit" and len(body_toks) >= 4 and body_toks[2].lower() in {"tunnel", "ipsec-vpn"}:
                pol.vpn_action = body_toks[2].lower()
                ref_index = 4 if body_toks[2].lower() == "tunnel" and body_toks[3].lower() == "ipsec-vpn" else 3
                if len(body_toks) > ref_index:
                    pol.vpn_reference = body_toks[ref_index]
            if len(body_toks) > 2:
                # permit sub-options
                safe_body_toks = sanitize_tokens(body_toks)
                pol.permit_option_paths.append(safe_body_toks[2:])
                pol.permit_options["_".join(safe_body_toks[2:])] = sanitize_source_attributes(
                    {"raw": cmd.raw_sanitized}
                )
                if body_toks[2].lower() == "application-services":
                    pol.application_services.extend(v for v in extract_value_list(body_toks[3:]) if v not in pol.application_services)
                elif body_toks[2].lower() in {"utm-policy", "idp-policy", "ssl-proxy-profile", "security-intelligence"}:
                    pol.security_profile_references.setdefault(body_toks[2].lower(), []).extend(
                        v for v in extract_value_list(body_toks[3:]) if v not in pol.security_profile_references.setdefault(body_toks[2].lower(), [])
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
            if log_type == "session-close":
                pol.log_session_close = True
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            pol.logging_options.append({"type": log_type, "values": body_toks[3:]})
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True
        elif then_act == "count":
            pol.count = True
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_body_toks = sanitize_tokens(body_toks)
        pol.unknown_then_options["_".join(safe_body_toks[1:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    safe_body_toks = sanitize_tokens(body_toks)
    pol.source_attributes["_".join(safe_body_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
