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
    JuniperPersistentNAT,
)
from fwmigrate.parsers.juniper_srx.provenance import record_member_candidate, record_scalar_candidate
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
                    value = {"start": toks[3], "end": toks[to_idx + 1]}
                    record_member_candidate(pool.member_candidate_history, "address_ranges", value, cmd)
                    pool.address_ranges.append(value)
                    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                    cmd.requires_manual_review = True
                    return True
            addrs = extract_value_list(toks[3:])
            for a in addrs:
                record_member_candidate(pool.member_candidate_history, "addresses", a, cmd)
                if a not in pool.addresses:
                    pool.addresses.append(a)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub in {"address-range", "address-range-start"} and len(toks) >= 5:
            value = {"start": toks[3], "end": toks[4]}
            record_member_candidate(pool.member_candidate_history, "address_ranges", value, cmd)
            pool.address_ranges.append(value)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        elif sub == "port" and len(toks) >= 4:
            ports = extract_value_list(toks[3:])
            for p in ports:
                record_member_candidate(pool.member_candidate_history, "ports", p, cmd)
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
                _record_context(rs, "from_zone", rs.from_context.zones, vals, cmd)
            elif ctx_type == "interface":
                _record_context(rs, "from_interface", rs.from_context.interfaces, vals, cmd)
            elif ctx_type == "routing-instance":
                _record_context(rs, "from_routing_instance", rs.from_context.routing_instances, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif nat_type == "source" and sub == "to" and len(toks) >= 5:
            if not rs.to_context:
                rs.to_context = JuniperNATContext()
            ctx_type = toks[3].lower()
            vals = extract_value_list(toks[4:])
            if ctx_type == "zone":
                _record_context(rs, "to_zone", rs.to_context.zones, vals, cmd)
            elif ctx_type == "interface":
                _record_context(rs, "to_interface", rs.to_context.interfaces, vals, cmd)
            elif ctx_type == "routing-instance":
                _record_context(rs, "to_routing_instance", rs.to_context.routing_instances, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif nat_type == "destination" and sub == "to":
            _record_unsupported_nat_context(rs, toks, cmd)
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
                _record_context(rs, "from_zone", rs.from_context.zones, vals, cmd)
            elif ctx_type == "interface":
                _record_context(rs, "from_interface", rs.from_context.interfaces, vals, cmd)
            elif ctx_type == "routing-instance":
                _record_context(rs, "from_routing_instance", rs.from_context.routing_instances, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "to":
            _record_unsupported_nat_context(rs, toks, cmd)
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


def _record_unsupported_nat_context(rs: JuniperNATRuleSet, toks: list[str], cmd: JunosCommand) -> None:
    rs.source_attributes.setdefault("unsupported_contexts", []).append(
        sanitize_source_attributes({"tokens": toks, "raw": cmd.raw_sanitized})
    )
    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
    cmd.requires_manual_review = True


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
        record_scalar_candidate(rule.field_provenance, rule.field_candidate_history, "description", rule.description, cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    if key == "disable":
        rule.disabled = True
        record_scalar_candidate(rule.field_provenance, rule.field_candidate_history, "disabled", True, cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    # Match criteria
    if key == "match" and len(body_toks) >= 3:
        match_key = body_toks[1].lower()
        vals = extract_value_list(body_toks[2:])
        if any(":" in value for value in vals):
            rule.nat_family = "ipv6"

        if match_key == "source-address":
            _record_match(rule, "source_addresses", rule.match.source_addresses, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-address":
            _record_match(rule, "destination_addresses", rule.match.destination_addresses, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "source-address-name":
            _record_match(rule, "source_address_names", rule.match.source_address_names, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-address-name":
            _record_match(rule, "destination_address_names", rule.match.destination_address_names, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "source-port":
            _record_match(rule, "source_ports", rule.match.source_ports, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "destination-port":
            _record_match(rule, "destination_ports", rule.match.destination_ports, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "protocol":
            _record_match(rule, "protocols", rule.match.protocols, vals, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif match_key == "application":
            _record_match(rule, "applications", rule.match.applications, vals, cmd)
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
                action = {"type": "pool", "pool_name": body_toks[3],
                          **({"persistent_nat": rule.action["persistent_nat"]}
                             if rule.action.get("persistent_nat") else {})}
                if len(body_toks) > 4:
                    return _parse_persistent_nat(cmd, body_toks[5:], rule, action)
                _record_action(rule, action, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "interface":
                action = {"type": "interface",
                          **({"persistent_nat": rule.action["persistent_nat"]}
                             if rule.action.get("persistent_nat") else {})}
                if len(body_toks) > 3:
                    return _parse_persistent_nat(cmd, body_toks[4:], rule, action)
                _record_action(rule, action, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "off":
                _record_action(rule, {"type": "off"}, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            else:
                safe_action_toks = sanitize_tokens(body_toks[1:])
                _record_action(rule, {"type": "unknown", "raw": " ".join(safe_action_toks)}, cmd)
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
                return True
        elif then_type == "destination-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub == "pool" and len(body_toks) >= 4:
                _record_action(rule, {"type": "pool", "pool_name": body_toks[3]}, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "off":
                _record_action(rule, {"type": "off"}, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            else:
                safe_action_toks = sanitize_tokens(body_toks[1:])
                _record_action(rule, {"type": "unknown", "raw": " ".join(safe_action_toks)}, cmd)
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
                return True
        elif then_type == "static-nat" and len(body_toks) >= 3:
            sub = body_toks[2].lower()
            if sub in {"prefix", "prefix-name"}:
                if len(body_toks) < 4:
                    if sub == "prefix" and rule.action.get("type") == "static_prefix":
                        _record_action(rule, {
                            "type": "static_prefix",
                            "prefix": rule.action.get("prefix"),
                        }, cmd)
                    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
                    cmd.requires_manual_review = True
                    return True
                value = body_toks[3]
                if value.lower() in {"mapped-port", "routing-instance"}:
                    return _parse_static_nat_child(cmd, body_toks[2:], rule)
                field = "static_prefix" if sub == "prefix" else "static_prefix_name"
                action_type = field
                action = _static_action_with_selector(rule, action_type, value)
                record_scalar_candidate(
                    rule.field_provenance, rule.field_candidate_history, field, value, cmd
                )
                _record_action(rule, action, cmd)
                if sub == "prefix-name":
                    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                    cmd.requires_manual_review = True
                    return True
                try:
                    ipaddress.ip_network(value, strict=False)
                    cmd.extraction_status = ExtractionStatus.NORMALIZED
                except ValueError:
                    cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                    cmd.parse_error = f"Invalid static NAT prefix '{value}'"
                    cmd.requires_manual_review = True
                return True
            elif sub == "mapped-port":
                return _parse_static_nat_child(
                    cmd, ["prefix", "mapped-port", *body_toks[3:]], rule
                )

            # Do not turn an invalid static-NAT hierarchy into a new action.
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            cmd.requires_manual_review = True
            return True

        safe_action_toks = sanitize_tokens(body_toks[1:])
        _record_action(rule, {"type": "unknown", "raw": " ".join(safe_action_toks)}, cmd)
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    safe_body_toks = sanitize_tokens(body_toks)
    rule.source_attributes["_".join(safe_body_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _record_context(rs, field, target, values, cmd):
    for value in values:
        record_member_candidate(rs.member_candidate_history, field, value, cmd)
        if value not in target:
            target.append(value)


def _record_match(rule, field, target, values, cmd):
    for value in values:
        record_member_candidate(rule.match.member_candidate_history, field, value, cmd)
        if value not in target:
            target.append(value)


def _record_action(rule, action, cmd):
    record_scalar_candidate(rule.field_provenance, rule.field_candidate_history, "action", action, cmd)
    rule.action = action


_PERSISTENT_NAT_PERMITS = {"any-remote-host", "target-host", "target-server"}


def _parse_persistent_nat(cmd: JunosCommand, toks: list[str], rule: JuniperNATRule, action: dict) -> bool:
    persistent = action.get("persistent_nat") or JuniperPersistentNAT()
    if not toks:
        _record_action(rule, {**action, "persistent_nat": persistent}, cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    key = toks[0].lower()
    field = key.replace("-", "_")
    if key == "address-mapping" and len(toks) == 1:
        persistent.address_mapping = True
        record_scalar_candidate(persistent.field_provenance, persistent.field_candidate_history,
                                "address_mapping", True, cmd)
    elif key in {"inactivity-timeout", "max-session-number"} and len(toks) == 2:
        try:
            value = int(toks[1])
            if value < 0:
                raise ValueError
        except ValueError:
            _record_persistent_unknown(persistent, toks, cmd)
            _record_action(rule, {**action, "persistent_nat": persistent}, cmd)
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
            return True
        setattr(persistent, field, value)
        record_scalar_candidate(persistent.field_provenance, persistent.field_candidate_history,
                                field, value, cmd)
    elif key == "permit" and len(toks) == 2 and toks[1].lower() in _PERSISTENT_NAT_PERMITS:
        persistent.permit = toks[1].lower()
        record_scalar_candidate(persistent.field_provenance, persistent.field_candidate_history,
                                "permit", persistent.permit, cmd)
    else:
        _record_persistent_unknown(persistent, toks, cmd)
        _record_action(rule, {**action, "persistent_nat": persistent}, cmd)
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    _record_action(rule, {**action, "persistent_nat": persistent}, cmd)
    cmd.extraction_status = ExtractionStatus.NORMALIZED
    return True


def _record_persistent_unknown(persistent: JuniperPersistentNAT, toks: list[str], cmd: JunosCommand) -> None:
    persistent.source_attributes.setdefault("unknown_children", []).append(
        sanitize_source_attributes({"tokens": toks, "raw": cmd.raw_sanitized})
    )


def _static_action_with_selector(rule: JuniperNATRule, action_type: str, value: str) -> dict:
    action = {key: value for key, value in (
        ("mapped_port", rule.action.get("mapped_port")),
        ("mapped_port_start", rule.action.get("mapped_port_start")),
        ("mapped_port_end", rule.action.get("mapped_port_end")),
        ("routing_instance", rule.action.get("routing_instance")),
    ) if value is not None}
    action["type"] = action_type
    action["prefix" if action_type == "static_prefix" else "prefix_name"] = value
    return action


def _parse_static_nat_child(cmd: JunosCommand, toks: list[str], rule: JuniperNATRule) -> bool:
    child = toks[1].lower() if len(toks) > 1 else ""
    if child == "routing-instance" and len(toks) == 3:
        value = toks[2]
        record_scalar_candidate(
            rule.field_provenance, rule.field_candidate_history, "routing_instance", value, cmd
        )
        action = dict(rule.action)
        action["routing_instance"] = value
        _record_action(rule, action, cmd)
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    if child == "mapped-port" and len(toks) >= 3:
        values = toks[2:]
        if len(values) == 1:
            start = end = values[0]
        elif len(values) == 3 and values[1].lower() == "to":
            start, end = values[0], values[2]
        else:
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            cmd.requires_manual_review = True
            return True
        try:
            if not (0 <= int(start) <= 65535 and 0 <= int(end) <= 65535):
                raise ValueError
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Invalid static NAT mapped-port '{' '.join(values)}'"
            cmd.requires_manual_review = True
            return True
        record_scalar_candidate(
            rule.field_provenance,
            rule.field_candidate_history,
            "mapped_port",
            {"start": start, "end": end},
            cmd,
        )
        action = dict(rule.action)
        action.update(mapped_port=start if start == end else f"{start}-{end}",
                      mapped_port_start=start, mapped_port_end=end)
        _record_action(rule, action, cmd)
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    cmd.requires_manual_review = True
    return True
