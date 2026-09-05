import xml.etree.ElementTree as ET
from typing import Optional

from fwmigrate.ir.core import IRPANLogServerEndpoint, IRPANLogServerProfile, IRPANLogForwardingMatch, IRPANLogForwardingProfile, IRPANManagementLogSetting
from .source_model import PANScope, PANSourceObject, pan_scope_identity
from .extraction import record_extract_only, record_parse_error, record_unsupported
from .residual import record_unknown_children
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _bool(node: Optional[ET.Element], path: str, reasons: list[str]) -> Optional[bool]:
    value = text_or_none(node, path)
    if value is None: return None
    if value == "yes": return True
    if value == "no": return False
    reasons.append(f"Invalid PAN yes/no value at {path}: {value}")
    return None

def _int(node: Optional[ET.Element], path: str, reasons: list[str]) -> Optional[int]:
    value = text_or_none(node, path)
    if value is None: return None
    try: return int(value)
    except ValueError:
        reasons.append(f"Invalid integer at {path}: {value}"); return None

def _refs(entry: ET.Element, tag: str) -> list[str]:
    return member_texts(entry, f"./{tag}/member") or ([v.text.strip() for v in entry.findall(f"./{tag}") if v.text and v.text.strip()] if entry.find(f"./{tag}") is not None else [])

def _server_entries(entry, family):
    paths = {
        "syslog": ("./server/entry", "./servers/entry"),
        "email": ("./server/entry", "./servers/entry"),
        "snmptrap": ("./version/v2c/server/entry", "./version/v3/server/entry", "./server/entry"),
        "http": ("./server/entry", "./servers/entry"),
    }
    for path in paths[family]:
        entries = entry.findall(path)
        if entries:
            return entries
    return []


def _profile(scope, family, entry, extraction):
    name = entry.get("name")
    if not name:
        record_parse_error(extraction, "pan_log_servers", f"log-settings/{family}/entry", scope, attributes={"pan_source_entry": structured_xml_capture(entry)}, notes=["PAN log server profile is missing its name."])
        return None
    endpoints = []
    profile_reasons = []
    source = sanitize_source_attributes(structured_xml_capture(entry))
    known = {'server', 'servers'} if family in {'syslog', 'email', 'http'} else {'version', 'server', 'servers'}
    record_unknown_children(extraction, entry, known, scope, f'log-settings/{family}/entry[@name="{name}"]', 'pan_log_servers', f'Unknown PAN {family} log profile child.')
    for server in _server_entries(entry, family):
        reasons = []
        address = text_or_none(server, "./address")
        if family == "snmptrap":
            address = text_or_none(server, "./manager") or address
        to_addresses = _refs(server, "to") if family == "email" else []
        version = "v2c" if entry.find("./version/v2c") is not None and server.find("./manager") is not None else ("v3" if entry.find("./version/v3") is not None else text_or_none(server, "./version"))
        endpoint = IRPANLogServerEndpoint(
            name=server.get("name") or "server", address=text_or_none(server, "./address"),
            transport=text_or_none(server, "./transport"), port=_int(server, "./port", reasons),
            format=text_or_none(server, "./format"), facility=text_or_none(server, "./facility"),
            display_name=text_or_none(server, "./display-name"), gateway=text_or_none(server, "./gateway"),
            from_address=text_or_none(server, "./from"), to_addresses=to_addresses,
            snmp_version=version,
            community_configured=server.find("./community") is not None,
            username=text_or_none(server, "./username"),
            authentication_password_configured=server.find("./authentication-password") is not None,
            privacy_password_configured=server.find("./privacy-password") is not None,
            source_attributes=sanitize_source_attributes(structured_xml_capture(server)),
        )
        endpoint.address = address
        if family == "snmptrap" and endpoint.community_configured:
            endpoint.source_attributes.pop("community", None)
        endpoints.append(endpoint)
        profile_reasons.extend(reasons)
        record_unknown_children(extraction, server, {
            'name', 'address', 'manager', 'transport', 'port', 'format',
            'facility', 'display-name', 'gateway', 'from', 'to', 'version',
            'community', 'username', 'authentication-password',
            'privacy-password', 'server',
        }, scope, f'log-settings/{family}/entry[@name="{name}"]/server/entry', 'pan_log_servers', f'Unknown PAN {family} log server child.')
    return IRPANLogServerProfile(name=name, source_context=pan_scope_identity(scope), profile_type=family, servers=endpoints, review_reasons=profile_reasons, source_attributes=source)

def _match(entry: ET.Element) -> IRPANLogForwardingMatch:
    reasons=[]
    return IRPANLogForwardingMatch(name=entry.get("name") or "<unnamed>", log_type=text_or_none(entry,"./log-type"), filter=text_or_none(entry,"./filter"), send_to_panorama=_bool(entry,"./send-to-panorama",reasons), syslog_profiles=_refs(entry,"send-syslog"), email_profiles=_refs(entry,"send-email"), snmptrap_profiles=_refs(entry,"send-snmptrap"), http_profiles=_refs(entry,"send-http"), review_reasons=reasons, source_attributes=sanitize_source_attributes(structured_xml_capture(entry)))

def extract_pan_logging(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    ir = extraction.canonical_ir
    log = root.find("./log-settings")
    if log is not None:
        for family in ("syslog", "email", "snmptrap", "http"):
            for entry in log.findall(f"./{family}/entry"):
                profile = _profile(scope, family, entry, extraction)
                if profile:
                    ir.pan_log_server_profiles.append(profile)
                    resolver.register_object(PANSourceObject(domain="pan_log_server", kind=family, source_path=f"log-settings/{family}/entry", name=profile.name, scope=scope, ir_object=profile), f"pan-{family}-profile" if family != "http" else "pan-http-log-profile")
                    record_extract_only(extraction,"pan_log_servers",f"log-settings/{family}/entry[@name='{profile.name}']",scope,profile.name,profile.source_attributes,notes=["PAN log server profile is source-only."] ,requires_manual_review=True)
        for entry in log.findall("./system/match-list/entry"):
            record_unknown_children(extraction, entry, {'send-syslog', 'send-email', 'send-snmptrap', 'send-http', 'log-type', 'filter', 'send-to-panorama'}, scope, 'log-settings/system/match-list/entry', 'pan_management_log_settings', 'Unknown PAN log match child.')
            match=IRPANManagementLogSetting(**_match(entry).model_dump(), log_family="system")
            match.source_attributes["pan_source_context"] = pan_scope_identity(scope)
            ir.pan_management_log_settings.append(match)
            record_extract_only(extraction,"pan_management_log_settings","log-settings/system/match-list/entry",scope,match.name,match.source_attributes,notes=["PAN management log setting is source-only."],requires_manual_review=True)
        for entry in log.findall("./profiles/entry"):
            record_unknown_children(extraction, entry, {'match-list'}, scope, 'log-settings/profiles/entry', 'pan_log_forwarding_profiles', 'Unknown PAN log forwarding profile child.')
            matches = [_match(m) for m in entry.findall("./match-list/entry")]
            for match in matches:
                record_unknown_children(extraction, next(m for m in entry.findall('./match-list/entry') if (m.get('name') or '<unnamed>') == match.name), {'send-syslog', 'send-email', 'send-snmptrap', 'send-http', 'log-type', 'filter', 'send-to-panorama'}, scope, 'log-settings/profiles/entry/match-list/entry', 'pan_log_forwarding_profiles', 'Unknown PAN log match child.')
                match.source_attributes["pan_source_context"] = pan_scope_identity(scope)
            profile=IRPANLogForwardingProfile(name=entry.get("name") or "<unnamed>", source_context=pan_scope_identity(scope), matches=matches, source_attributes=sanitize_source_attributes(structured_xml_capture(entry)))
            ir.pan_log_forwarding_profiles.append(profile)
            resolver.register_object(PANSourceObject(domain="pan_log_forwarding", kind="profile", source_path="log-settings/profiles/entry", name=profile.name, scope=scope, ir_object=profile), "pan-log-forwarding-profile")
            record_extract_only(extraction,"pan_log_forwarding_profiles","log-settings/profiles/entry",scope,profile.name,profile.source_attributes,notes=["PAN log forwarding profile is source-only."],requires_manual_review=True)

def finalize_advanced_logging_references(extraction, resolver) -> None:
    def scope_for(value):
        parts = (value or "").split(":")
        if len(parts) >= 2:
            return PANScope(kind=parts[0], name=parts[1], vsys=parts[1] if parts[0] == "vsys" else None,
                            device_serial=parts[3] if len(parts) > 3 and parts[2] == "device" else None)
        return None
    kinds=(("syslog_profiles","pan-syslog-profile"),("email_profiles","pan-email-profile"),("snmptrap_profiles","pan-snmptrap-profile"),("http_profiles","pan-http-log-profile"))
    def resolve_match(match, scope):
        for attr, kind in kinds:
            refs = getattr(match, attr)
            resolved = getattr(match, f"resolved_{attr}")
            unresolved = getattr(match, f"unresolved_{attr}")
            for ref in refs:
                obj = resolver.resolve(ref, kind, scope)
                if obj:
                    resolved.append(obj.canonical_name or ref)
                else:
                    unresolved.append(ref)
                    reason = f"Unresolved PAN log profile reference: {ref}"
                    if reason not in match.review_reasons:
                        match.review_reasons.append(reason)
    for profile in extraction.canonical_ir.pan_log_forwarding_profiles:
        scope = scope_for(profile.source_context)
        for match in profile.matches:
            resolve_match(match, scope)
    for match in extraction.canonical_ir.pan_management_log_settings:
        resolve_match(match, scope_for(match.source_attributes.get("pan_source_context")))
    for policy in extraction.canonical_ir.policies:
        if not policy.source_log_setting:
            continue
        obj = resolver.resolve(policy.source_log_setting, "pan-log-forwarding-profile", scope_for(policy.source_context))
        policy.source_log_setting_resolved = obj is not None
        policy.resolved_source_log_setting = obj.canonical_name if obj else None
        if not obj:
            reason = f"Unresolved PAN policy log-setting reference: {policy.source_log_setting}"
            if reason not in policy.review_reasons:
                policy.review_reasons.append(reason)
            policy.requires_manual_review = True
    for zone in extraction.canonical_ir.zones:
        if not zone.source_log_setting:
            continue
        obj = resolver.resolve(zone.source_log_setting, "pan-log-forwarding-profile", scope_for(zone.source_attributes.get("pan_source_context")))
        if obj:
            zone.source_log_setting_resolved = obj.canonical_name or zone.source_log_setting
            zone.resolved_source_log_setting = zone.source_log_setting_resolved
        else:
            zone.source_log_setting_resolved = False
            reason = f"Unresolved PAN zone log-setting reference: {zone.source_log_setting}"
            if reason not in zone.review_reasons:
                zone.review_reasons.append(reason)
            zone.requires_manual_review = True
