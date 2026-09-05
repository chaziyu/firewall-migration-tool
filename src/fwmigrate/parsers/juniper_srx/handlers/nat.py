"""Handler for Junos NAT (source, destination, static, pools, rule-sets, and proxy-arp/ndp) configuration hierarchy."""

from __future__ import annotations

import ipaddress

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig,
    JuniperNATContext,
    JuniperNATPool,
    JuniperNATRule,
    JuniperNATRuleSet,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_nat_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set security nat ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "security" or toks[2].lower() != "nat":
        return False

    cmd.consumed = True
    cmd.handler = "nat"

    if len(toks) < 4:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    nat_sub = toks[3].lower()

    if nat_sub in {"nptv6", "nat66"}:
        # Keep NPTv6 distinct from ordinary source NAT; it is not an IPv4 translation.
        context.nat.source_attributes.setdefault("ipv6", []).append(
            sanitize_source_attributes({"nat_family": "nptv6", "raw": cmd.raw_sanitized})
        )
        cmd.consumed, cmd.handler = True, "nat"
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        cmd.requires_manual_review = True
        return True

    # 1. Proxy ARP
    if nat_sub == "proxy-arp" and len(toks) >= 4:
        context.nat.proxy_arp.append(
            sanitize_source_attributes({"raw": cmd.raw_sanitized})
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # 2. Proxy NDP
    if nat_sub == "proxy-ndp" and len(toks) >= 4:
        context.nat.proxy_ndp.append(
            sanitize_source_attributes({"raw": cmd.raw_sanitized})
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # 3. Source NAT
    if nat_sub == "source" and len(toks) >= 5:
        return _handle_source_or_dest_nat(cmd, toks[4:], context, nat_type="source")

    # 4. Destination NAT
    if nat_sub == "destination" and len(toks) >= 5:
        return _handle_source_or_dest_nat(cmd, toks[4:], context, nat_type="destination")

    # 5. Static NAT
    if nat_sub == "static" and len(toks) >= 5:
        return _handle_static_nat(cmd, toks[4:], context)

    safe_toks = sanitize_tokens(toks)
    context.nat.source_attributes["_".join(safe_toks[3:])] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _handle_source_or_dest_nat(
    cmd: JunosCommand,
    toks: list[str],
    context: JuniperContextConfig,
    nat_type: str,
) -> bool:
    target_pools = context.nat.source_pools if nat_type == "source" else context.nat.destination_pools
    target_rule_sets = context.nat.source_rule_sets if nat_type == "source" else context.nat.destination_rule_sets

    kind = toks[0].lower()

    # Pool definition: pool <pool_name> ...
    if kind == "pool" and len(toks) >= 2:
        pool_name = toks[1]
        if pool_name not in target_pools:
            target_pools[pool_name] = JuniperNATPool(name=pool_name, nat_type=nat_type)
        pool = target_pools[pool_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "address" and len(toks) >= 4:
            if "to" in [t.lower() for t in toks[3:]]:
                to_idx = [t.lower() for t in toks[3:]].index("to") + 3
                if to_idx > 3 and to_idx + 1 < len(toks):
                    pool.address_ranges.append({"start": toks[3], "end": toks[to_idx + 1]})
                    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                    cmd.requires_manual_review = True
                    return True
            addrs = extract_value_list(toks[3:])
            for a in addrs:
                if a not in pool.addresses:
                    pool.addresses.append(a)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub in {"address-range", "address-range-start"} and len(toks) >= 5:
            pool.address_ranges.append({"start": toks[3], "end": toks[4]})
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif sub == "port" and len(toks) >= 4:
            ports = extract_value_list(toks[3:])
            for p in ports:
                if p not in pool.ports:
                    pool.ports.append(p)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub not in {"address", "port"}:
            pool.options["_".join(sanitize_tokens(toks[2:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True

        safe_toks = sanitize_tokens(toks)
        pool.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # Rule-set definition: rule-set <rs_name> ...
    if kind == "rule-set" and len(toks) >= 2:
        rs_name = toks[1]
        if rs_name not in target_rule_sets:
            target_rule_sets[rs_name] = JuniperNATRuleSet(name=rs_name, nat_type=nat_type)
        rs = target_rule_sets[rs_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "from" and len(toks) >= 5:
            ctx_type = toks[3].lower()
            vals = extract_value_list(toks[4:])
            if ctx_type == "zone":
                rs.from_context.zones.extend([v for v in vals if v not in rs.from_context.zones])
            elif ctx_type == "interface":
                rs.from_context.interfaces.extend([v for v in vals if v not in rs.from_context.interfaces])
            elif ctx_type == "routing-instance":
                rs.from_context.routing_instances.extend([v for v in vals if v not in rs.from_context.routing_instances])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "to" and len(toks) >= 5:
            if not rs.to_context:
                rs.to_context = JuniperNATContext()
            ctx_type = toks[3].lower()
            vals = extract_value_list(toks[4:])
            if ctx_type == "zone":
                rs.to_context.zones.extend([v for v in vals if v not in rs.to_context.zones])
            elif ctx_type == "interface":
                rs.to_context.interfaces.extend([v for v in vals if v not in rs.to_context.interfaces])
            elif ctx_type == "routing-instance":
                rs.to_context.routing_instances.extend([v for v in vals if v not in rs.to_context.routing_instances])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "rule" and len(toks) >= 4:
            rule_name = toks[3]
            rule = _get_or_create_nat_rule(rs, rule_name, nat_type)
            if len(toks) == 4:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_nat_rule_body(cmd, toks[4:], rule)

        safe_toks = sanitize_tokens(toks)
        rs.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False


def _handle_static_nat(cmd: JunosCommand, toks: list[str], context: JuniperContextConfig) -> bool:
    kind = toks[0].lower()
    if kind == "rule-set" and len(toks) >= 2:
        rs_name = toks[1]
        if rs_name not in context.nat.static_rule_sets:
            context.nat.static_rule_sets[rs_name] = JuniperNATRuleSet(name=rs_name, nat_type="static")
        rs = context.nat.static_rule_sets[rs_name]

        if len(toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = toks[2].lower()
        if sub == "from" and len(toks) >= 5:
            ctx_type = toks[3].lower()
            vals = extract_value_list(toks[4:])
            if ctx_type == "zone":
                rs.from_context.zones.extend([v for v in vals if v not in rs.from_context.zones])
            elif ctx_type == "interface":
                rs.from_context.interfaces.extend([v for v in vals if v not in rs.from_context.interfaces])
            elif ctx_type == "routing-instance":
                rs.from_context.routing_instances.extend([v for v in vals if v not in rs.from_context.routing_instances])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "rule" and len(toks) >= 4:
            rule_name = toks[3]
            rule = _get_or_create_nat_rule(rs, rule_name, "static")
            if len(toks) == 4:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_nat_rule_body(cmd, toks[4:], rule)

        safe_toks = sanitize_tokens(toks)
        rs.source_attributes["_".join(safe_toks[2:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False


def _get_or_create_nat_rule(rs: JuniperNATRuleSet, name: str, nat_type: str) -> JuniperNATRule:
    for r in rs.rules:
        if r.name == name:
            return r
    new_r = JuniperNATRule(name=name, nat_type=nat_type, sequence=len(rs.rules) + 1)
    rs.rules.append(new_r)
    return new_r


def _parse_nat_rule_body(cmd: JunosCommand, body_toks: list[str], rule: JuniperNATRule) -> bool:
    if not body_toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    key = body_toks[0].lower()

    if key == "description" and len(body_toks) >= 2:
        rule.description = " ".join(body_toks[1:])
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    if key == "disable":
        rule.disabled = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    # Match criteria
    if key == "match" and len(body_toks) >= 3:
        match_key = body_toks[1].lower()
        vals = extract_value_list(body_toks[2:])
        if any(":" in value for value in vals):
            rule.nat_family = "ipv6"

        if match_key == "source-address":
            rule.match.source_addresses.extend([v for v in vals if v not in rule.match.source_addresses])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-address":
            rule.match.destination_addresses.extend([v for v in vals if v not in rule.match.destination_addresses])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "source-address-name":
            rule.match.source_address_names.extend([v for v in vals if v not in rule.match.source_address_names])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-address-name":
            rule.match.destination_address_names.extend([v for v in vals if v not in rule.match.destination_address_names])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "source-port":
            rule.match.source_ports.extend([v for v in vals if v not in rule.match.source_ports])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-port":
            rule.match.destination_ports.extend([v for v in vals if v not in rule.match.destination_ports])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "protocol":
            rule.match.protocols.extend([v for v in vals if v not in rule.match.protocols])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "application":
            rule.match.applications.extend([v for v in vals if v not in rule.match.applications])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        # Unknown match condition: DO NOT append to source_addresses!
        safe_match_toks = sanitize_tokens(body_toks[1:])
        condition_str = " ".join(safe_match_toks)
        rule.match.unknown_match_conditions.append(condition_str)
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    if key == "then" and len(body_toks) >= 2:
        then_type = body_toks[1].lower()
        if then_type == "source-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "pool" and len(body_toks) >= 4:
                rule.action.update({"type": "pool", "pool_name": body_toks[3]})
                if len(body_toks) > 4:
                    rule.action.setdefault("persistent_nat", []).append(body_toks[4:])
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "interface":
                rule.action.update({"type": "interface"})
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "off":
                rule.action.update({"type": "off"})
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            else:
                safe_action_toks = sanitize_tokens(body_toks[1:])
                rule.action = {"type": "unknown", "raw": " ".join(safe_action_toks)}
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
                return True
        elif then_type == "destination-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "pool" and len(body_toks) >= 4:
                rule.action.update({"type": "pool", "pool_name": body_toks[3]})
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "off":
                rule.action.update({"type": "off"})
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            else:
                safe_action_toks = sanitize_tokens(body_toks[1:])
                rule.action = {"type": "unknown", "raw": " ".join(safe_action_toks)}
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
                return True
        elif then_type == "static-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "prefix" and len(body_toks) >= 4:
                prefix_val = body_toks[3]
                try:
                    ipaddress.ip_network(prefix_val, strict=False)
                    rule.action.update({"type": "static_prefix", "prefix": prefix_val})
                    cmd.extraction_status = ExtractionStatus.NORMALIZED
                except ValueError:
                    rule.action.update({"type": "static_prefix", "prefix": prefix_val})
                    cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                    cmd.parse_error = f"Invalid static NAT prefix '{prefix_val}'"
                    cmd.requires_manual_review = True
                return True
            elif sub == "prefix-name" and len(body_toks) >= 4:
                rule.action.update({"type": "static_prefix_name", "prefix_name": body_toks[3]})
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
                return True
            elif sub == "mapped-port" and len(body_toks) >= 4:
                rule.action["mapped_port"] = body_toks[3]
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
                return True

        safe_action_toks = sanitize_tokens(body_toks[1:])
        rule.action = {"type": "unknown", "raw": " ".join(safe_action_toks)}
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    safe_body_toks = sanitize_tokens(body_toks)
    rule.source_attributes["_".join(safe_body_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
