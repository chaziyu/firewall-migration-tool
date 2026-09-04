import xml.etree.ElementTree as ET
from typing import Optional

from fwmigrate.ir.core import IRPANLogServerEndpoint, IRPANLogServerProfile, IRPANLogForwardingMatch, IRPANLogForwardingProfile, IRPANManagementLogSetting
from .source_model import PANScope, PANSourceObject, pan_scope_identity
from .extraction import record_extract_only, record_parse_error
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

def _profile(scope, family, entry, extraction):
    name = entry.get("name")
    if not name:
        record_parse_error(extraction, "pan_log_servers", f"log-settings/{family}/entry", scope, attributes={"pan_source_entry": structured_xml_capture(entry)}, notes=["PAN log server profile is missing its name."])
        return None
    endpoints = []
    source = sanitize_source_attributes(structured_xml_capture(entry))
    for server in entry.findall("./server/entry") or entry.findall("./servers/entry"):
        reasons = []
        endpoint = IRPANLogServerEndpoint(
            name=server.get("name") or "server", address=text_or_none(server, "./address"),
            transport=text_or_none(server, "./transport"), port=_int(server, "./port", reasons),
            format=text_or_none(server, "./format"), facility=text_or_none(server, "./facility"),
            display_name=text_or_none(server, "./display-name"), gateway=text_or_none(server, "./gateway"),
            from_address=text_or_none(server, "./from"), to_addresses=_refs(server, "to"),
            snmp_version=text_or_none(server, "./version"),
            community_configured=server.find("./community") is not None,
            username=text_or_none(server, "./username"),
            authentication_password_configured=server.find("./authentication-password") is not None,
            privacy_password_configured=server.find("./privacy-password") is not None,
            source_attributes=sanitize_source_attributes(structured_xml_capture(server)),
        )
        endpoints.append(endpoint)
    return IRPANLogServerProfile(name=name, source_context=pan_scope_identity(scope), profile_type=family, servers=endpoints, source_attributes=source)

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
            match=_match(entry); match.log_family="system"
            ir.pan_management_log_settings.append(match)
            record_extract_only(extraction,"pan_management_log_settings","log-settings/system/match-list/entry",scope,match.name,match.source_attributes,notes=["PAN management log setting is source-only."],requires_manual_review=True)
        for entry in log.findall("./profiles/entry"):
            profile=IRPANLogForwardingProfile(name=entry.get("name") or "<unnamed>", source_context=pan_scope_identity(scope), matches=[_match(m) for m in entry.findall("./match-list/entry")], source_attributes=sanitize_source_attributes(structured_xml_capture(entry)))
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
    for profile in extraction.canonical_ir.pan_log_forwarding_profiles:
        scope = scope_for(profile.source_context)
        for match in profile.matches:
            for attr, kind in kinds:
                refs=getattr(match,attr)
                for ref in refs:
                    obj=resolver.resolve(ref,kind,scope)
                    if obj: refs[refs.index(ref)]=obj.canonical_name or ref
                    else: match.review_reasons.append(f"Unresolved PAN log profile reference: {ref}")
    for zone in extraction.canonical_ir.zones:
        if not zone.source_log_setting:
            continue
        obj = resolver.resolve(zone.source_log_setting, "pan-log-forwarding-profile", scope_for(zone.source_attributes.get("pan_source_context")))
        if obj:
            zone.source_log_setting_resolved = obj.canonical_name or zone.source_log_setting
            zone.resolved_source_log_setting = zone.source_log_setting_resolved
        else:
            zone.source_attributes.setdefault("pan_review_reasons", []).append(f"Unresolved PAN zone log-setting reference: {zone.source_log_setting}")
