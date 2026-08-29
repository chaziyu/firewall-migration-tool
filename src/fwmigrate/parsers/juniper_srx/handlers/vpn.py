"""Handler for Junos VPN (IKE proposals/policies/gateways, IPsec proposals/policies/vpns) configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig,
    JuniperIKEGateway,
    JuniperIKEPolicy,
    JuniperIKEProposal,
    JuniperIPSecPolicy,
    JuniperIPSecProposal,
    JuniperIPSecVPN,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_vpn_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set security ike ...' and 'set security ipsec ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "security":
        return False

    sub = toks[2].lower()
    if sub == "ike":
        cmd.consumed = True
        cmd.handler = "vpn"
        return _handle_ike(cmd, toks[3:], context)
    elif sub == "ipsec":
        cmd.consumed = True
        cmd.handler = "vpn"
        return _handle_ipsec(cmd, toks[3:], context)

    return False


def _handle_ike(cmd: JunosCommand, toks: list[str], context: JuniperContextConfig) -> bool:
    if not toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    kind = toks[0].lower()

    # 1. IKE proposal: proposal <name> ...
    if kind == "proposal" and len(toks) >= 2:
        prop_name = toks[1]
        if prop_name not in context.vpn.ike_proposals:
            context.vpn.ike_proposals[prop_name] = JuniperIKEProposal(name=prop_name)
        prop = context.vpn.ike_proposals[prop_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "authentication-method" and len(toks) >= 4:
            prop.authentication_method = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "dh-group" and len(toks) >= 4:
            prop.dh_group = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "authentication-algorithm" and len(toks) >= 4:
            prop.authentication_algorithm = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "encryption-algorithm" and len(toks) >= 4:
            prop.encryption_algorithm = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "lifetime-seconds" and len(toks) >= 4:
            try:
                prop.lifetime_seconds = int(toks[3])
                cmd.extraction_status = ExtractionStatus.NORMALIZED
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            return True

        safe_toks = sanitize_tokens(toks)
        prop.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # 2. IKE policy: policy <name> ...
    if kind == "policy" and len(toks) >= 2:
        pol_name = toks[1]
        if pol_name not in context.vpn.ike_policies:
            context.vpn.ike_policies[pol_name] = JuniperIKEPolicy(name=pol_name)
        pol = context.vpn.ike_policies[pol_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "mode" and len(toks) >= 4:
            pol.mode = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "proposal-set" and len(toks) >= 4:
            pol.proposal_set = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "proposals" and len(toks) >= 4:
            props = extract_value_list(toks[3:])
            for p in props:
                if p not in pol.proposals:
                    pol.proposals.append(p)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "pre-shared-key":
            pol.has_pre_shared_key = True
            pol.source_attributes["pre_shared_key"] = "[REDACTED]"
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_toks = sanitize_tokens(toks)
        pol.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # 3. IKE gateway: gateway <name> ...
    if kind == "gateway" and len(toks) >= 2:
        gw_name = toks[1]
        if gw_name not in context.vpn.ike_gateways:
            context.vpn.ike_gateways[gw_name] = JuniperIKEGateway(name=gw_name)
        gw = context.vpn.ike_gateways[gw_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "ike-policy" and len(toks) >= 4:
            gw.ike_policy = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "address" and len(toks) >= 4:
            gw.address = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "external-interface" and len(toks) >= 4:
            gw.external_interface = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "version" and len(toks) >= 4:
            gw.version = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "local-address" and len(toks) >= 4:
            gw.local_address = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_toks = sanitize_tokens(toks)
        gw.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False


def _handle_ipsec(cmd: JunosCommand, toks: list[str], context: JuniperContextConfig) -> bool:
    if not toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    kind = toks[0].lower()

    # 1. IPsec proposal: proposal <name> ...
    if kind == "proposal" and len(toks) >= 2:
        prop_name = toks[1]
        if prop_name not in context.vpn.ipsec_proposals:
            context.vpn.ipsec_proposals[prop_name] = JuniperIPSecProposal(name=prop_name)
        prop = context.vpn.ipsec_proposals[prop_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "protocol" and len(toks) >= 4:
            prop.protocol = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "authentication-algorithm" and len(toks) >= 4:
            prop.authentication_algorithm = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "encryption-algorithm" and len(toks) >= 4:
            prop.encryption_algorithm = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "lifetime-seconds" and len(toks) >= 4:
            try:
                prop.lifetime_seconds = int(toks[3])
                cmd.extraction_status = ExtractionStatus.NORMALIZED
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            return True

        safe_toks = sanitize_tokens(toks)
        prop.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # 2. IPsec policy: policy <name> ...
    if kind == "policy" and len(toks) >= 2:
        pol_name = toks[1]
        if pol_name not in context.vpn.ipsec_policies:
            context.vpn.ipsec_policies[pol_name] = JuniperIPSecPolicy(name=pol_name)
        pol = context.vpn.ipsec_policies[pol_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "proposals" and len(toks) >= 4:
            props = extract_value_list(toks[3:])
            for p in props:
                if p not in pol.proposals:
                    pol.proposals.append(p)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "proposal-set" and len(toks) >= 4:
            pol.proposal_set = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "perfect-forward-secrecy" and len(toks) >= 5 and toks[3].lower() == "keys":
            pol.pfs_group = toks[4]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_toks = sanitize_tokens(toks)
        pol.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # 3. IPsec VPN: vpn <name> ...
    if kind == "vpn" and len(toks) >= 2:
        vpn_name = toks[1]
        if vpn_name not in context.vpn.ipsec_vpns:
            context.vpn.ipsec_vpns[vpn_name] = JuniperIPSecVPN(name=vpn_name)
        vpn = context.vpn.ipsec_vpns[vpn_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "bind-interface" and len(toks) >= 4:
            vpn.bind_interface = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "establish-tunnels" and len(toks) >= 4:
            vpn.establish_tunnels = toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "ike" and len(toks) >= 5:
            ike_sub = toks[3].lower()
            if ike_sub == "gateway":
                vpn.ike_gateway = toks[4]
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif ike_sub == "ipsec-policy":
                vpn.ipsec_policy = toks[4]
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True

        safe_toks = sanitize_tokens(toks)
        vpn.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False
