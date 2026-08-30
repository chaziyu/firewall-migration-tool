"""Structured source-only parsers for PAN-OS policy families without canonical IR."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error
from .source_model import PANScope
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


COMMON_FIELDS = [
    "from", "to", "source", "destination", "source-user", "service", "application",
    "action", "disabled", "description", "tag", "group-tag", "log-start", "log-end",
    "log-setting", "schedule", "negate-source", "negate-destination",
]

FAMILY_FIELDS: Dict[str, List[str]] = {
    "decryption": ["category", "profile", "type", "source-hip", "destination-hip"],
    "application-override": ["protocol", "port", "application", "source-user"],
    "authentication": ["authentication-enforcement", "timeout", "source-hip", "destination-hip"],
    "pbf": ["enforce-symmetric-return", "forward", "monitor", "source-user", "source-hip"],
    "qos": ["class", "dscp-marking", "source-user"],
    "dos": ["protect", "protection", "source-zone", "destination-zone", "source-interface"],
    "tunnel-inspect": ["tunnel-protocol", "profile", "source-user"],
    "tunnel-inspection": ["tunnel-protocol", "profile", "source-user"],
    "sdwan": ["path-quality-profile", "traffic-distribution-profile", "source-user"],
    "network-packet-broker": ["profile", "device", "source-user"],
}


def _entries(root: ET.Element, container: str, family: str) -> Iterable[ET.Element]:
    return root.findall(f"./{container}/{family}/rules/entry")


def _parse_family(root: ET.Element, scope: PANScope, extraction, family: str) -> int:
    total = 0
    canonical_family = "tunnel-inspect" if family == "tunnel-inspection" else family
    for position, container in (("pre", "pre-rulebase"), ("local", "rulebase"),
                                ("post", "post-rulebase")):
        entries = list(_entries(root, container, family))
        for index, entry in enumerate(entries):
            name = entry.get("name")
            path = f"{container}/{family}/rules/entry[@name='{name}']"
            source_rule_id = f"palo_alto:{scope.kind}:{scope.name}:{position}:{canonical_family}:{index}:{name}"
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
    return _parse_family(root, scope, extraction, "pbf")


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
