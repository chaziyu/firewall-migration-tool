"""PAN-OS External Dynamic List source inventory."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .extraction import add_source_section, record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.models import ExtractionStatus


def extract_external_lists(scope: PANScope, search_root: ET.Element, extraction) -> None:
    container = search_root.find("./external-dynamic-list")
    if container is None:
        return
    entries = container.findall("./entry")
    if not entries:
        record_unsupported(
            extraction, "external_dynamic_lists", "external-dynamic-list", scope,
            "external-dynamic-list", {"pan_source_entry": structured_xml_capture(container)},
            notes=["PAN-OS external dynamic list container has no recognized entries."],
        )
        add_source_section(
            extraction, "external-dynamic-list", ExtractionStatus.UNSUPPORTED,
            1, 1, 0, "extract_external_lists", source_context=f"{scope.kind}:{scope.name}",
        )
        return
    parsed = 0
    for entry in entries:
        name = entry.get("name")
        path = f"external-dynamic-list/entry[@name='{name}']" if name else "external-dynamic-list/entry"
        type_node = entry.find("./type")
        type_children = [child.tag for child in type_node] if type_node is not None else []
        list_type = text_or_none(entry, "./type") or (type_children[0] if len(type_children) == 1 else None)
        recurring = entry.find("./recurring")
        authentication = entry.find("./authentication")
        attributes = {
            "pan_list_type": list_type,
            "pan_type_children": type_children,
            "pan_url": text_or_none(entry, "./type/url"),
            "pan_urls": member_texts(entry, "./type/url/member") or member_texts(entry, "./type/url"),
            "pan_ip_url": text_or_none(entry, "./type/ip/url"),
            "pan_domain_url": text_or_none(entry, "./type/domain/url"),
            "pan_certificate_profile": text_or_none(entry, "./type/certificate-profile"),
            "pan_authentication": structured_xml_capture(authentication),
            "pan_authentication_username": text_or_none(authentication, "./username"),
            "pan_authentication_password_configured": authentication is not None and authentication.find("./password") is not None,
            "pan_update_schedule": structured_xml_capture(recurring),
            "pan_update_interval": text_or_none(recurring, "./interval"),
            "pan_update_frequency": text_or_none(recurring, "./frequency"),
            "pan_exceptions": structured_xml_capture(entry.find("./exceptions")) or structured_xml_capture(entry.find("./exception")),
            "pan_description": text_or_none(entry, "./description"),
            "pan_unknown_fields": collect_unknown_children(entry, [
                "type", "recurring", "description", "authentication", "exceptions", "exception",
            ]),
            "pan_source_entry": structured_xml_capture(entry),
        }
        attributes = {key: value for key, value in attributes.items() if value is not None}
        if not name:
            record_parse_error(
                extraction, "external_dynamic_lists", path, scope, None, attributes,
                notes=["PAN-OS external dynamic list is missing its required name."],
            )
            continue
        record_extract_only(
            extraction, "external_dynamic_lists", path, scope, name, attributes,
            notes=["PAN-OS external dynamic list retained as source-only inventory; target list semantics are not generated."],
            requires_manual_review=True,
        )
        parsed += 1
    add_source_section(
        extraction, "external-dynamic-list", ExtractionStatus.EXTRACT_ONLY,
        len(entries), parsed, 0, "extract_external_lists",
        source_context=f"{scope.kind}:{scope.name}",
    )
