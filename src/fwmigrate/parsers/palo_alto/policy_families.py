"""Structured source-only parsers for PAN-OS policy families without canonical IR."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error
from .pbf import PANPBFRuleExtractor
from .source_model import PANScope, pan_scope_identity
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


COMMON_FIELDS = [
    "from", "to", "source", "destination", "source-user", "service", "application",
    "user", "from-zone", "to-zone", "from-interface", "to-interface", "hip",
    "action", "disabled", "description", "tag", "group-tag", "log-start", "log-end",
    "log-setting", "schedule", "negate-source", "negate-destination",
]

FAMILY_FIELDS: Dict[str, List[str]] = {
    "decryption": ["category", "profile", "type", "source-hip", "destination-hip", "decrypt-action"],
    "application-override": ["protocol", "port", "application", "source-user", "override"],
    "authentication": ["authentication-enforcement", "timeout", "source-hip", "destination-hip", "authentication-profile"],
    "qos": ["class", "qos-class", "dscp", "dscp-marking", "tos", "source-user", "category", "hip"],
    "dos": ["protect", "protection", "classified", "aggregate", "profile", "source-zone", "destination-zone", "source-interface"],
    "tunnel-inspect": ["tunnel-protocol", "tunnel-id", "profile", "source-user", "inspect", "monitor"],
    "tunnel-inspection": ["tunnel-protocol", "tunnel-id", "profile", "source-user", "inspect", "monitor"],
    "sdwan": ["path-quality-profile", "traffic-distribution-profile", "saas-quality-profile", "error-correction", "failover", "source-user"],
    "network-packet-broker": ["profile", "device", "source-user", "forwarding", "interface"],
}


def _entries(root: ET.Element, container: str, family: str) -> Iterable[ET.Element]:
    return root.findall(f"./{container}/{family}/rules/entry")


def _typed_fields(entry: ET.Element, family: str) -> Dict[str, Any]:
    if family == "decryption":
        return {"pan_decryption_category": member_texts(entry, "./category/member") or ([text_or_none(entry, "./category")] if text_or_none(entry, "./category") else []), "pan_decryption_profile": text_or_none(entry, "./profile"), "pan_decrypt_action": text_or_none(entry, "./decrypt-action") or text_or_none(entry, "./action"), "pan_decryption_source_hip": member_texts(entry, "./source-hip/member"), "pan_decryption_destination_hip": member_texts(entry, "./destination-hip/member")}
    if family == "application-override":
        return {"pan_override_protocol": text_or_none(entry, "./protocol"), "pan_override_ports": member_texts(entry, "./port/member") or ([text_or_none(entry, "./port")] if text_or_none(entry, "./port") else []), "pan_override_applications": member_texts(entry, "./application/member") or ([text_or_none(entry, "./application")] if text_or_none(entry, "./application") else []), "pan_override_action": text_or_none(entry, "./override") or text_or_none(entry, "./action")}
    if family == "authentication":
        return {"pan_authentication_enforcement": text_or_none(entry, "./authentication-enforcement"), "pan_authentication_timeout": text_or_none(entry, "./timeout"), "pan_authentication_profile": text_or_none(entry, "./authentication-profile"), "pan_authentication_action": text_or_none(entry, "./action")}
    if family == "qos":
        return {"pan_qos_classes": member_texts(entry, "./class/member") or ([text_or_none(entry, "./class")] if text_or_none(entry, "./class") else []), "pan_qos_class": text_or_none(entry, "./qos-class"), "pan_qos_dscp": text_or_none(entry, "./dscp"), "pan_qos_dscp_marking": structured_xml_capture(entry.find("./dscp-marking")) if entry.find("./dscp-marking") is not None else None, "pan_qos_tos": text_or_none(entry, "./tos")}
    if family == "dos":
        node = entry.find("./protect")
        if node is None:
            node = entry.find("./protection")
        return {"pan_dos_protection": structured_xml_capture(node) if node is not None else None, "pan_dos_profile": text_or_none(entry, "./profile"), "pan_dos_action": text_or_none(entry, "./action"), "pan_dos_source_zones": member_texts(entry, "./source-zone/member"), "pan_dos_destination_zones": member_texts(entry, "./destination-zone/member")}
    if family in {"tunnel-inspect", "tunnel-inspection"}:
        monitor = entry.find("./monitor")
        return {"pan_tunnel_protocol": text_or_none(entry, "./tunnel-protocol"), "pan_tunnel_ids": member_texts(entry, "./tunnel-id/member") or ([text_or_none(entry, "./tunnel-id")] if text_or_none(entry, "./tunnel-id") else []), "pan_tunnel_profile": text_or_none(entry, "./profile"), "pan_tunnel_action": text_or_none(entry, "./action"), "pan_tunnel_inspect": text_or_none(entry, "./inspect"), "pan_tunnel_monitor": structured_xml_capture(monitor) if monitor is not None else None}
    return {}


def _parse_family(root: ET.Element, scope: PANScope, extraction, family: str) -> int:
    total = 0
    canonical_family = "tunnel-inspect" if family == "tunnel-inspection" else family
    for position, container in (("pre", "pre-rulebase"), ("local", "rulebase"),
                                ("post", "post-rulebase")):
        entries = list(_entries(root, container, family))
        for index, entry in enumerate(entries):
            name = entry.get("name")
            path = f"{container}/{family}/rules/entry[@name='{name}']"
            source_rule_id = f"palo_alto:{pan_scope_identity(scope)}:{position}:{canonical_family}:{index}:{name}"
            known = COMMON_FIELDS + FAMILY_FIELDS[family]
            family_specific: Dict[str, Any] = {}
            for child_name in FAMILY_FIELDS[family]:
                child = entry.find(f"./{child_name}")
                if child is not None:
                    family_specific[child_name] = structured_xml_capture(child)
            attributes = {
                "pan_policy_family": canonical_family,
                "pan_scope_kind": scope.kind,
                "pan_scope_name": scope.name,
                "pan_rulebase_position": position,
                "pan_source_rule_index": index,
                "pan_source_rule_id": source_rule_id,
                "pan_from": member_texts(entry, "./from/member"),
                "pan_to": member_texts(entry, "./to/member"),
                "pan_source": member_texts(entry, "./source/member"),
                "pan_destination": member_texts(entry, "./destination/member"),
                "pan_source_user": member_texts(entry, "./source-user/member"),
                "pan_service": member_texts(entry, "./service/member"),
                "pan_application": member_texts(entry, "./application/member"),
                "pan_action": text_or_none(entry, "./action"),
                "pan_disabled": text_or_none(entry, "./disabled"),
                "pan_description": text_or_none(entry, "./description"),
                "pan_tags": member_texts(entry, "./tag/member"),
                "pan_group_tag": text_or_none(entry, "./group-tag"),
                "pan_log_start": text_or_none(entry, "./log-start"),
                "pan_log_end": text_or_none(entry, "./log-end"),
                "pan_log_setting": text_or_none(entry, "./log-setting"),
                "pan_family_specific": family_specific,
                "pan_unknown_fields": collect_unknown_children(entry, known),
                "pan_source_entry": structured_xml_capture(entry),
            }
            if family == "sdwan":
                attributes.update({
                    "pan_path_quality_profile": text_or_none(entry, "./path-quality-profile"),
                    "pan_traffic_distribution_profile": text_or_none(entry, "./traffic-distribution-profile"),
                    "pan_sdwan_tags": member_texts(entry, "./tag/member"),
                    "pan_sdwan_action": text_or_none(entry, "./action"),
                    "pan_sdwan_failover": structured_xml_capture(entry.find("./failover")) if entry.find("./failover") is not None else None,
                    "pan_sdwan_description": text_or_none(entry, "./description"),
                    "pan_sdwan_disabled": text_or_none(entry, "./disabled"),
                })
            attributes.update(_typed_fields(entry, family))
            if scope.device_serial:
                attributes["pan_device_serial"] = scope.device_serial
            if not name:
                record_parse_error(
                    extraction, f"policy:{canonical_family}", path, scope, None, attributes,
                    notes=[f"PAN-OS {canonical_family} rule is missing its required name."],
                )
            else:
                record_extract_only(
                    extraction, f"policy:{canonical_family}", path, scope, name, attributes,
                    notes=[f"PAN-OS {canonical_family} rule retained as structured source-only policy evidence."],
                    requires_manual_review=True,
                )
            total += 1
        if entries:
            add_source_section(
                extraction, f"{container}/{family}/rules", ExtractionStatus.EXTRACT_ONLY,
                len(entries), len(entries), 0, f"parse_{canonical_family.replace('-', '_')}_rules",
                source_context=f"{scope.kind}:{scope.name}",
            )
    return total


def parse_decryption_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "decryption")


def parse_application_override_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "application-override")


def parse_authentication_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "authentication")


def parse_pbf_rules(root, scope, extraction):
    return PANPBFRuleExtractor.parse_rules(root, scope, extraction)


def parse_qos_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "qos")


def parse_dos_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "dos")


def parse_tunnel_inspect_rules(root, scope, extraction):
    return (_parse_family(root, scope, extraction, "tunnel-inspect") +
            _parse_family(root, scope, extraction, "tunnel-inspection"))


def parse_sdwan_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "sdwan")


def parse_network_packet_broker_rules(root, scope, extraction):
    return _parse_family(root, scope, extraction, "network-packet-broker")


def parse_policy_families(root: ET.Element, scope: PANScope, extraction) -> None:
    for parser in (
        parse_decryption_rules, parse_application_override_rules, parse_authentication_rules,
        parse_pbf_rules, parse_qos_rules, parse_dos_rules, parse_tunnel_inspect_rules,
        parse_sdwan_rules, parse_network_packet_broker_rules,
    ):
        parser(root, scope, extraction)
