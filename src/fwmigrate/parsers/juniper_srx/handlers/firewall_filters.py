"""Extract Junos stateless firewall filters without treating them as policies."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperFirewallFilter, JuniperFirewallFilterTerm
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_firewall_filter_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
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
        term = JuniperFirewallFilterTerm(name=term_name)
        filt.terms.append(term)
    rest = t[8:]
    if rest and rest[0].lower() == "then":
        term.actions.append(sanitize_source_attributes({"action": extract_value_list(rest[1:]) or True}))
    elif rest:
        term.matches.setdefault(rest[0], []).extend(extract_value_list(rest[1:]) or [True])
    else:
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
