"""Extract Junos stateless firewall filters without treating them as policies."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperFirewallFilter, JuniperFirewallFilterTerm, JuniperPolicer
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_firewall_filter_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) >= 4 and t[1:3] == ["firewall", "policer"]:
        obj = context.policers.setdefault(t[3], JuniperPolicer(name=t[3]))
        cmd.consumed, cmd.handler = True, "policers"
        key, values = (t[4].lower(), t[5:]) if len(t) > 4 else ("", [])
        if key in {"bandwidth-limit", "bandwidth-percent"} and values:
            obj.bandwidth_limit = " ".join(values)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        elif key in {"burst-size-limit", "burst-limit"} and values:
            obj.burst_limit = " ".join(values)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        elif key == "then" and values:
            obj.action = " ".join(values)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        else:
            obj.source_attributes["_".join(sanitize_tokens(t[4:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    if len(t) < 6 or t[1].lower() != "firewall" or t[2].lower() != "family" or t[4].lower() != "filter":
        return False
    family, name = t[3], t[5]
    if not name:
        return False
    filt = context.firewall_filters.setdefault(name, JuniperFirewallFilter(name=name, family=family))
    cmd.consumed, cmd.handler = True, "firewall-filters"
    if len(t) == 6:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    if t[6].lower() != "term" or len(t) < 8:
        filt.source_attributes["_".join(sanitize_tokens(t[6:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    term_name = t[7]
    term = next((x for x in filt.terms if x.name == term_name), None)
    if term is None:
        term = JuniperFirewallFilterTerm(
            name=term_name,
            source_order=cmd.source_order or cmd.line_number,
        )
        filt.terms.append(term)
    rest = t[8:]
    if not rest:
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    if rest[0].lower() == "from" and len(rest) >= 2:
        field = rest[1].lower()
        values = extract_value_list(rest[2:])
        supported = {
            "source-address", "destination-address", "source-port",
            "destination-port", "protocol", "ip-version", "forwarding-class",
            "forwarding-class-except", "source-prefix-list", "destination-prefix-list",
        }
        if field in supported and values:
            term.matches.setdefault(field, []).extend(
                value for value in values if value not in term.matches.setdefault(field, [])
            )
            term.from_conditions.append(
                sanitize_source_attributes({"field": field, "values": values})
            )
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        term.from_conditions.append(
            sanitize_source_attributes({"path": rest[1:], "values": values or [True]})
        )
        term.matches.setdefault(field, []).extend(values or [True])
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    if rest[0].lower() == "then" and len(rest) >= 2:
        action = rest[1].lower()
        values = extract_value_list(rest[2:])
        supported = {"accept", "discard", "reject", "routing-instance", "next-hop"}
        if action in supported and (action in {"accept", "discard", "reject"} or values):
            entry = {"action": [action] if action in {"accept", "discard", "reject"} else action}
            if values:
                entry["value"] = values[0] if len(values) == 1 else values
                if action == "routing-instance":
                    entry["routing_instance"] = entry["value"]
                elif action == "next-hop":
                    entry["next_hop"] = entry["value"]
            term.actions.append(sanitize_source_attributes(entry))
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        term.actions.append(
            sanitize_source_attributes({"action": action, "values": values})
        )
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return True

    term.source_attributes.setdefault("unsupported", []).append(
        sanitize_source_attributes({"path": rest, "raw": cmd.raw_sanitized})
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
