"""Extract access profiles and firewall-authentication clients."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.vendors.juniper_srx.model import (
    JuniperAccessClient, JuniperAccessFirewallUser, JuniperAccessProfile,
    JuniperContextConfig,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand


def handle_access_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "access":
        return False
    profile_pos = next((i for i, token in enumerate(toks) if token.lower() == "profile"), -1)
    if profile_pos < 0 or profile_pos + 1 >= len(toks):
        return False
    name = toks[profile_pos + 1]
    profile = context.access_profiles.setdefault(name, JuniperAccessProfile(name=name))
    tail = toks[profile_pos + 2:]
    lower = [token.lower() for token in tail]
    if "client" in lower and lower.index("client") + 1 < len(tail):
        pos = lower.index("client")
        client_name = tail[pos + 1]
        client = profile.clients.setdefault(client_name, JuniperAccessClient(name=client_name))
        child = tail[pos + 2:]
        child_lower = [token.lower() for token in child]
        if child_lower[:1] == ["firewall-user"]:
            user = client.firewall_user or JuniperAccessFirewallUser(name=client_name)
            if "password" in child_lower:
                user.password_configured = True
                status = ExtractionStatus.EXTRACTED
            else:
                safe = sanitize_tokens(child)
                if len(safe) > 1:
                    user.settings["_".join(safe[1:])] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
                status = ExtractionStatus.PARTIAL
            user.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
            client.firewall_user = user
        elif child_lower[:1] == ["client-group"] and len(child) > 1:
            value = child[1]
            if value not in client.client_groups:
                client.client_groups.append(value)
            status = ExtractionStatus.EXTRACTED
        else:
            client.settings["_".join(sanitize_tokens(child))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            status = ExtractionStatus.SOURCE_ONLY
        client.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    else:
        profile.settings["_".join(sanitize_tokens(tail))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        status = ExtractionStatus.SOURCE_ONLY
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "access", status
    return True
