from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANDefaultSecurityRule, PANProfileSetting, PANSecurityRule
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, structured_xml_capture, typed_fields, value, values


def _profile(element: ET.Element) -> PANProfileSetting | None:
    node = element.find("profile-setting")
    if node is None:
        return None
    profiles_node = node.find("profiles")
    profiles = {child.tag: values(profiles_node, child.tag) or [] for child in profiles_node} if profiles_node is not None else None
    extra, explicit = typed_fields(node, {"group", "profiles"}, {"group": "groups"})
    if profiles_node is not None:
        profiles_extra = {}
        for child in profiles_node:
            child_extra = raw_extra(child, {"member"})
            if child_extra:
                profiles_extra[child.tag] = child_extra
        if profiles_extra:
            extra["profiles-extra"] = profiles_extra
    return PANProfileSetting(groups=values(node, "group"), profiles=profiles, raw_extra=extra, explicit_fields={"groups" if item == "group" else item for item in explicit})


def _fields(element: ET.Element, spec: PANPathSpec):
    extra, explicit = source_fields(element, spec)
    explicit.discard("option")
    return extra, explicit


def _common(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int) -> dict[str, object]:
    return {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order, "rulebase_position": context.rulebase_position}


def extract_security_rule(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANSecurityRule | None:
    extra, explicit = _fields(element, spec)
    return PANSecurityRule(**_common(element, path, context, source_order), from_zones=values(element, "from"), to_zones=values(element, "to"), source=values(element, "source"), destination=values(element, "destination"), source_user=values(element, "source-user"), application=values(element, "application"), service=values(element, "service"), category=values(element, "category"), source_hip=values(element, "source-hip"), destination_hip=values(element, "destination-hip"), negate_source=value(element, "negate-source"), negate_destination=value(element, "negate-destination"), schedule=value(element, "schedule"), action=value(element, "action"), rule_type=value(element, "rule-type"), description=value(element, "description"), tags=values(element, "tag"), group_tag=value(element, "group-tag"), log_start=value(element, "log-start"), log_end=value(element, "log-end"), log_setting=value(element, "log-setting"), disabled=value(element, "disabled"), profile_setting=_profile(element), disable_inspect=value(element, "disable-inspect"), disable_server_response_inspection=value(element, "disable-server-response-inspection"), icmp_unreachable=value(element, "icmp-unreachable"), saas_user_list=values(element, "saas-user-list"), saas_tenant_list=values(element, "saas-tenant-list"), raw_extra=extra, explicit_fields=explicit)


def extract_default_security_rule(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANDefaultSecurityRule | None:
    extra, explicit = _fields(element, spec)
    direct = value(element, "disable-server-response-inspection")
    option = element.find("option")
    nested = value(option, "disable-server-response-inspection")
    if nested is not None:
        explicit.add("disable_server_response_inspection")
    if direct is not None and nested is not None:
        extra["conflicting-source-fields"] = {"disable-server-response-inspection": {"direct": direct, "option": structured_xml_capture(option)}}
        resolved = direct if direct == nested else None
    else:
        resolved = direct if direct is not None else nested
    return PANDefaultSecurityRule(**_common(element, path, context, source_order), action=value(element, "action"), disabled=value(element, "disabled"), log_start=value(element, "log-start"), log_end=value(element, "log-end"), log_setting=value(element, "log-setting"), description=value(element, "description"), tags=values(element, "tag"), group_tag=value(element, "group-tag"), profile_setting=_profile(element), disable_server_response_inspection=resolved, icmp_unreachable=value(element, "icmp-unreachable"), raw_extra=extra, explicit_fields=explicit)


def extract_policy(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    """Compatibility dispatcher for callers of the original extractor name."""
    return extract_security_rule(element, path, context, source_order, spec) or extract_default_security_rule(element, path, context, source_order, spec)
