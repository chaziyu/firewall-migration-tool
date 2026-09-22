from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANDefaultSecurityRule, PANProfileSetting, PANSecurityRule
from ..source_context import PANWalkContext
from .common import typed_fields, value, values


def _profile(element: ET.Element) -> PANProfileSetting | None:
    node = element.find("profile-setting")
    if node is None:
        return None
    profiles_node = node.find("profiles")
    profiles = {child.tag: values(profiles_node, child.tag) or [] for child in profiles_node} if profiles_node is not None else None
    extra, explicit = typed_fields(node, {"group", "profiles"})
    return PANProfileSetting(groups=values(node, "group"), profiles=profiles, raw_extra=extra, explicit_fields={"groups" if item == "group" else item for item in explicit})


def _fields(element: ET.Element, known: set[str]):
    extra, explicit = typed_fields(element, known)
    names = {"from": "from_zones", "to": "to_zones", "source-user": "source_user", "source-hip": "source_hip", "destination-hip": "destination_hip", "negate-source": "negate_source", "negate-destination": "negate_destination", "rule-type": "rule_type", "tag": "tags", "group-tag": "group_tag", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "profile-setting": "profile_setting", "disable-inspect": "disable_inspect", "disable-server-response-inspection": "disable_server_response_inspection", "saas-user-list": "saas_user_list", "saas-tenant-list": "saas_tenant_list"}
    return extra, {names.get(item, item) for item in explicit}


def extract_policy(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int) -> object | None:
    if len(path) < 3 or path[-1] != "entry" or path[-2] != "rules":
        return None
    rule_kind = path[-3]
    common = {"name": element.get("name"), "source_path": "/".join(path), "scope": context.scope, "source_order": source_order, "rulebase_position": context.rulebase_position}
    if rule_kind == "security":
        known = {"from", "to", "source", "destination", "source-user", "application", "service", "category", "source-hip", "destination-hip", "negate-source", "negate-destination", "schedule", "action", "rule-type", "description", "tag", "group-tag", "log-start", "log-end", "log-setting", "disabled", "profile-setting", "disable-inspect", "disable-server-response-inspection", "saas-user-list", "saas-tenant-list"}
        extra, explicit = _fields(element, known)
        return PANSecurityRule(**common, from_zones=values(element, "from"), to_zones=values(element, "to"), source=values(element, "source"), destination=values(element, "destination"), source_user=values(element, "source-user"), application=values(element, "application"), service=values(element, "service"), category=values(element, "category"), source_hip=values(element, "source-hip"), destination_hip=values(element, "destination-hip"), negate_source=value(element, "negate-source"), negate_destination=value(element, "negate-destination"), schedule=value(element, "schedule"), action=value(element, "action"), rule_type=value(element, "rule-type"), description=value(element, "description"), tags=values(element, "tag"), group_tag=value(element, "group-tag"), log_start=value(element, "log-start"), log_end=value(element, "log-end"), log_setting=value(element, "log-setting"), disabled=value(element, "disabled"), profile_setting=_profile(element), disable_inspect=value(element, "disable-inspect"), disable_server_response_inspection=value(element, "disable-server-response-inspection"), saas_user_list=values(element, "saas-user-list"), saas_tenant_list=values(element, "saas-tenant-list"), raw_extra=extra, explicit_fields=explicit)
    if rule_kind == "default-security-rules":
        known = {"action", "disabled", "log-start", "log-end", "log-setting", "description", "tag", "group-tag", "profile-setting", "disable-server-response-inspection", "option", "icmp-unreachable"}
        extra, explicit = _fields(element, known)
        option = element.find("option")
        nested = value(option, "disable-server-response-inspection")
        if nested is not None:
            explicit.add("disable_server_response_inspection")
        return PANDefaultSecurityRule(**common, action=value(element, "action"), disabled=value(element, "disabled"), log_start=value(element, "log-start"), log_end=value(element, "log-end"), log_setting=value(element, "log-setting"), description=value(element, "description"), tags=values(element, "tag"), group_tag=value(element, "group-tag"), profile_setting=_profile(element), disable_server_response_inspection=value(element, "disable-server-response-inspection") or nested, icmp_unreachable=value(element, "icmp-unreachable"), raw_extra=extra, explicit_fields=explicit)
    return None
