"""Handler for Junos NAT (source, destination, static, pools, rule-sets, and proxy-arp/ndp) configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes
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

    context.nat.source_attributes["_".join(toks[3:])] = sanitize_source_attributes(
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
            addrs = extract_value_list(toks[3:])
            for a in addrs:
                if a not in pool.addresses:
                    pool.addresses.append(a)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "port" and len(toks) >= 4:
            ports = extract_value_list(toks[3:])
            for p in ports:
                if p not in pool.ports:
                    pool.ports.append(p)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        pool.source_attributes["_".join(toks[2:])] = sanitize_source_attributes(
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

        rs.source_attributes["_".join(toks[2:])] = sanitize_source_attributes(
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

        rs.source_attributes["_".join(toks[2:])] = sanitize_source_attributes(
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
        rule.description = body_toks[1]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    if key == "match" and len(body_toks) >= 2:
        match_key = body_toks[1].lower()
        vals = extract_value_list(body_toks[2:]) if len(body_toks) > 2 else []

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

        rule.match.source_addresses.append("_".join(body_toks[1:]))
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        return True

    if key == "then" and len(body_toks) >= 2:
        then_type = body_toks[1].lower()
        if then_type == "source-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "pool" and len(body_toks) >= 4:
                rule.action = {"type": "pool", "pool_name": body_toks[3]}
            elif sub == "interface":
                rule.action = {"type": "interface"}
            elif sub == "off":
                rule.action = {"type": "off"}
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif then_type == "destination-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "pool" and len(body_toks) >= 4:
                rule.action = {"type": "pool", "pool_name": body_toks[3]}
            elif sub == "off":
                rule.action = {"type": "off"}
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif then_type == "static-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "prefix" and len(body_toks) >= 4:
                rule.action = {"type": "static_prefix", "prefix": body_toks[3]}
            elif sub == "prefix-name" and len(body_toks) >= 4:
                rule.action = {"type": "static_prefix_name", "prefix_name": body_toks[3]}
            elif sub == "mapped-port" and len(body_toks) >= 4:
                rule.action["mapped_port"] = body_toks[3]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        rule.action["raw"] = " ".join(body_toks[1:])
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    rule.source_attributes["_".join(body_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
