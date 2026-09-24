"""Extract Juniper Secure Connect's remote-access source objects."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.vendors.juniper_srx.model import (
    JuniperContextConfig, JuniperRemoteAccessApplicationBypassTerm,
    JuniperRemoteAccessClientConfig, JuniperRemoteAccessProfile,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_remote_access_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 3 or [x.lower() for x in t[1:3]] != ["security", "remote-access"]:
        return False
    tail = t[3:]
    low = [x.lower() for x in tail]
    if len(tail) < 2:
        return _source_only(cmd, context.remote_access.source_attributes)
    if low[0] == "profile":
        name = tail[1]
        obj = context.remote_access.profiles.setdefault(name, JuniperRemoteAccessProfile(name=name))
        props = tail[2:]
        plow = [x.lower() for x in props]
        fields = {"access-profile": "access_profile", "client-config": "client_config", "ipsec-vpn": "ipsec_vpn"}
        if props and plow[0] in fields and len(props) > 1:
            setattr(obj, fields[plow[0]], props[1])
            status = ExtractionStatus.EXTRACTED
        elif len(props) >= 2 and plow[0] == "options" and plow[1] == "multi-access":
            obj.multi_access = True
            status = ExtractionStatus.EXTRACTED
        elif props:
            obj.source_attributes.setdefault("commands", []).append(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
            status = ExtractionStatus.SOURCE_ONLY
        else:
            status = ExtractionStatus.EXTRACTED
        obj.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    elif low[0] == "client-config":
        name = tail[1]
        obj = context.remote_access.client_configs.setdefault(name, JuniperRemoteAccessClientConfig(name=name))
        props = tail[2:]
        plow = [x.lower() for x in props]
        if "application-bypass" in plow and "term" in plow:
            p = plow.index("term")
            if p + 1 < len(props):
                term_name = props[p + 1]
                term = obj.application_bypass_terms.setdefault(term_name, JuniperRemoteAccessApplicationBypassTerm(name=term_name))
                after = props[p + 2:]
                alow = [x.lower() for x in after]
                for key, attr in (("domain-name", "domain_names"), ("protocol", "protocols")):
                    if key in alow:
                        i = alow.index(key)
                        values = extract_value_list(after[i + 1:])
                        getattr(term, attr).extend(v for v in values if v not in getattr(term, attr))
                if "description" in alow and alow.index("description") + 1 < len(after):
                    term.description = " ".join(after[alow.index("description") + 1:])
                term.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
                status = ExtractionStatus.EXTRACTED if term.domain_names or term.protocols or term.description else ExtractionStatus.PARTIAL
            else:
                status = ExtractionStatus.SOURCE_ONLY
        else:
            obj.settings["_".join(sanitize_tokens(props))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            status = ExtractionStatus.SOURCE_ONLY if props else ExtractionStatus.EXTRACTED
        obj.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    else:
        return _source_only(cmd, context.remote_access.source_attributes)
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "remote_access", status
    return True


def _source_only(cmd: JunosCommand, target: dict) -> bool:
    target.setdefault("commands", []).append(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "remote_access", ExtractionStatus.SOURCE_ONLY
    return True
