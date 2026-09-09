"""Typed, source-oriented PAN-OS security profile inventories."""

from __future__ import annotations

from typing import Any, Iterable
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.core import (
    IRCustomURLCategory,
    IRSecurityProfileCredentialEnforcement,
    IRSecurityProfileDefinition,
    IRSecurityProfileRule,
)
from .extraction import add_source_section, record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope, PANSourceObject
from .xml_utils import member_texts, structured_xml_capture, text_or_none


PROFILE_FAMILIES = (
    "virus", "antivirus", "spyware", "anti-spyware", "vulnerability",
    "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering",
    "wildfire", "sctp", "gtp", "voip", "decryption", "decryption-profile", "dos-protection",
)
CANONICAL_FAMILIES = {"virus": "antivirus", "antivirus": "antivirus",
                     "spyware": "anti-spyware", "anti-spyware": "anti-spyware"}


def _profile_entries(search_root: ET.Element) -> Iterable[tuple[str, ET.Element, str]]:
    for container_name in ("profiles", "security-profiles"):
        container = search_root.find(f"./{container_name}")
        if container is None:
            continue
        for family_node in container:
            if family_node.tag in PROFILE_FAMILIES:
                for entry in family_node.findall("./entry"):
                    yield family_node.tag, entry, f"{container_name}/{family_node.tag}"


def _field_inventory(node: ET.Element) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    def walk(current: ET.Element, path: str) -> None:
        if current.text and current.text.strip() and not list(current):
            value: Any = current.text.strip()
            fields[path] = [*fields[path], value] if path in fields else [value]
        for child in current:
            walk(child, f"{path}/{child.tag}" if path else child.tag)
    walk(node, "")
    return fields


def _unknown_children(node: ET.Element, known: set[str]) -> dict[str, Any]:
    return {child.tag: structured_xml_capture(child) for child in node if child.tag not in known}


def _extract_rule_action(node: ET.Element, evidence: dict[str, Any], reasons: list[str]) -> str | None:
    action = node.find("./action")
    if action is None:
        return None
    children = list(action)
    if len(children) != 1 or not children[0].tag:
        evidence["pan_action_source"] = structured_xml_capture(action)
        reasons.append("invalid-action-structure")
        return None
    if action.text and action.text.strip():
        evidence["pan_action_source"] = structured_xml_capture(action)
        reasons.append("unexpected-action-text")
        return None
    return children[0].tag


def _rule(entry: ET.Element, family: str) -> IRSecurityProfileRule:
    evidence: dict[str, Any] = {}
    reasons: list[str] = []
    action = _extract_rule_action(entry, evidence, reasons)
    known = {"name", "application", "file-type", "direction", "action", "vendor-id",
             "severity", "cve", "threat-name", "host", "category", "packet-capture"}
    unknown = _unknown_children(entry, known)
    if unknown:
        evidence["pan_unknown_fields"] = unknown
    if reasons:
        evidence["pan_review_reasons"] = reasons
    return IRSecurityProfileRule(
        name=text_or_none(entry, "./name") or entry.get("name"),
        applications=member_texts(entry, "./application/member") or (["any"] if family == "file-blocking" and entry.find("./application") is not None else []),
        file_types=member_texts(entry, "./file-type/member") or (["any"] if family == "file-blocking" and entry.find("./file-type") is not None else []),
        direction=text_or_none(entry, "./direction"), action=action,
        vendor_ids=member_texts(entry, "./vendor-id/member"),
        severities=member_texts(entry, "./severity/member"), cves=member_texts(entry, "./cve/member"),
        threat_name=text_or_none(entry, "./threat-name"), host=text_or_none(entry, "./host"),
        category=text_or_none(entry, "./category"), packet_capture=text_or_none(entry, "./packet-capture"),
        source_attributes={"pan_rule_fields": _field_inventory(entry), **evidence},
    )


def _bool_value(entry: ET.Element, path: str, evidence: dict[str, Any], reasons: list[str]) -> bool | None:
    node = entry.find(f"./{path}")
    if node is None:
        return None
    value = (node.text or "").strip().lower()
    evidence[f"pan_{path.replace('-', '_')}_source"] = value
    if value not in {"yes", "no"}:
        reasons.append(f"invalid-{path}")
        return None
    return value == "yes"


def _definition(family: str, entry: ET.Element, scope: PANScope, custom_names: set[str]) -> IRSecurityProfileDefinition:
    name = entry.get("name") or ""
    evidence: dict[str, Any] = {"pan_profile_type": family,
        "pan_description": text_or_none(entry, "./description"),
        "pan_profile_settings": structured_xml_capture(entry),
        "pan_source_entry": structured_xml_capture(entry),
        "pan_profile_fields": _field_inventory(entry)}
    evidence = {key: value for key, value in evidence.items() if value is not None}
    reasons: list[str] = []
    rules = [_rule(rule, family) for rule in entry.findall("./rules/entry")]
    for rule in rules:
        reasons.extend(rule.source_attributes.get("pan_review_reasons", []))
    kwargs: dict[str, Any] = {}
    typed: dict[str, Any] = {}
    if family in {"decryption", "decryption-profile"}:
        typed = {"ssl_protocol": structured_xml_capture(entry.find("./ssl-protocol")),
                 "minimum_version": text_or_none(entry, "./ssl-protocol/min-version"),
                 "maximum_version": text_or_none(entry, "./ssl-protocol/max-version"),
                 "key_exchange": member_texts(entry, "./key-exchange/member"),
                 "ciphers": member_texts(entry, "./cipher/member") or member_texts(entry, "./ciphers/member")}
    elif family == "dos-protection":
        typed = {"flood_rates": structured_xml_capture(entry.find("./flood")),
                 "protocol_settings": structured_xml_capture(entry.find("./protocol")),
                 "aggregate": structured_xml_capture(entry.find("./aggregate")),
                 "protocol_thresholds": {
                     node.tag: structured_xml_capture(node)
                     for parent in (entry.find("./flood"), entry.find("./protocol")) if parent is not None
                     for node in parent
                 },
                 "block_settings": structured_xml_capture(entry.find("./block"))}
    if typed:
        evidence["pan_typed_profile_fields"] = typed
    if family == "url-filtering":
        for field in ("allow", "alert", "block", "continue", "override"):
            node = entry.find(f"./{field}")
            if node is not None:
                kwargs[f"{field}_categories"] = member_texts(node, "./member")
        credential = entry.find("./credential-enforcement")
        if credential is not None:
            mode_node = credential.find("./mode")
            mode = next((child.tag for child in mode_node), None) if mode_node is not None else None
            kwargs["credential_enforcement"] = IRSecurityProfileCredentialEnforcement(
                mode=mode, log_severity=text_or_none(credential, "./log-severity"),
                block_categories=member_texts(credential, "./block/member"),
                source_attributes={"pan_source": structured_xml_capture(credential)},
            )
        for field in ("log-http-hdr-xff", "log-http-hdr-user-agent"):
            kwargs[field.replace("-", "_")] = _bool_value(entry, field, evidence, reasons)
        refs = [value for field in ("allow", "alert", "block", "continue", "override") for value in kwargs.get(f"{field}_categories", []) if value in custom_names]
        if refs:
            evidence["pan_custom_url_category_references"] = refs
    unknown = _unknown_children(entry, {"description", "rules", "allow", "alert", "block", "continue", "override", "credential-enforcement", "log-http-hdr-xff", "log-http-hdr-user-agent", "ssl-protocol", "key-exchange", "cipher", "ciphers", "flood", "protocol", "aggregate"})
    if unknown:
        evidence["pan_unknown_fields"] = unknown
        reasons.append("unknown-profile-fields")
    return IRSecurityProfileDefinition(
        name=name, source_context=f"{scope.kind}:{scope.name}", family=CANONICAL_FAMILIES.get(family, family),
        source_family=family, description=text_or_none(entry, "./description"), rules=rules,
        review_reasons=list(dict.fromkeys(reasons)), source_attributes=evidence, **kwargs,
    )


def _extract_custom_url_categories(scope: PANScope, search_root: ET.Element, extraction, resolver) -> set[str]:
    container = search_root.find("./profiles/custom-url-category")
    if container is None:
        return set()
    parsed = 0
    names: set[str] = set()
    for entry in container.findall("./entry"):
        name = entry.get("name")
        path = f"profiles/custom-url-category/entry[@name='{name}']" if name else "profiles/custom-url-category/entry"
        attrs = {"pan_source_entry": structured_xml_capture(entry), "pan_profile_fields": _field_inventory(entry)}
        if not name:
            record_parse_error(extraction, "custom_url_categories", path, scope, attributes=attrs, notes=["PAN-OS custom URL category is missing its required name."])
            continue
        category = IRCustomURLCategory(name=name, source_context=f"{scope.kind}:{scope.name}", category_type=text_or_none(entry, "./type"), entries=member_texts(entry, "./list/member"), description=text_or_none(entry, "./description"), source_attributes={**attrs, "pan_unknown_fields": _unknown_children(entry, {"type", "list", "description"})})
        extraction.canonical_ir.custom_url_categories.append(category)
        resolver.register_object(PANSourceObject(name=name, kind="custom-url-category", domain="custom-url-category", source_path=path, scope=scope, attributes=attrs, ir_object=category), "custom-url-category")
        record_extract_only(extraction, "custom_url_categories", path, scope, name, attrs, requires_manual_review=True, notes=["PAN-OS custom URL category retained as typed source-only inventory."])
        names.add(name); parsed += 1
    add_source_section(extraction, "profiles/custom-url-category", ExtractionStatus.EXTRACT_ONLY, len(container.findall("./entry")), parsed, 0, "extract_security_profiles", f"{scope.kind}:{scope.name}")
    return names


def extract_security_profiles(scope: PANScope, search_root: ET.Element, extraction, resolver) -> None:
    custom_names = _extract_custom_url_categories(scope, search_root, extraction, resolver)
    entries = list(_profile_entries(search_root))
    parsed = 0
    for family, entry, prefix in entries:
        name = entry.get("name")
        path = f"{prefix}/entry[@name='{name}']" if name else f"{prefix}/entry"
        if not name:
            record_parse_error(extraction, "security_profiles", path, scope, attributes={"pan_source_entry": structured_xml_capture(entry)}, notes=["PAN-OS security profile is missing its required name."])
            continue
        definition = _definition(family, entry, scope, custom_names)
        source_object = PANSourceObject(name=name, kind="security-profile", domain="security-profile", source_path=path, scope=scope, attributes=definition.source_attributes, ir_object=definition)
        if not resolver.register_object(source_object, f"security-profile:{family}"):
            record_parse_error(extraction, "security_profiles", path, scope, name, definition.source_attributes, ["Duplicate PAN-OS security profile in the same family and scope."])
            continue
        resolver.register_object(source_object, "security-profile-reference")
        extraction.canonical_ir.security_profile_definitions.append(definition)
        record_extract_only(extraction, "security_profiles", path, scope, name, definition.source_attributes, [f"PAN-OS {family} security profile retained as typed source-only inventory."], True)
        parsed += 1
    containers = [search_root.find(f"./{name}") for name in ("profiles", "security-profiles")]
    unknown = [(container, family) for container in containers if container is not None for family in container if family.tag not in PROFILE_FAMILIES and family.tag != "custom-url-category"]
    for container, family in unknown:
        for index, entry in enumerate(family.findall("./entry") or [family]):
            record_unsupported(extraction, "security_profiles", f"{container.tag}/{family.tag}/entry[{index}]", scope, entry.get("name") or family.tag, {"pan_profile_family": family.tag, "pan_source_entry": structured_xml_capture(entry)}, [f"PAN-OS security profile family {family.tag} is not recognized by the extractor."])
    if entries or unknown:
        add_source_section(extraction, "profiles/security-profiles", ExtractionStatus.EXTRACT_ONLY, len(entries) + sum(len(f.findall("./entry")) or 1 for _, f in unknown), parsed, 0, "extract_security_profiles", f"{scope.kind}:{scope.name}")
