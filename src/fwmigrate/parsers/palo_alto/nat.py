"""Structured, direct-path PAN-OS NAT extraction."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATTranslationMode, NATType
from .source_model import PANScope
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none

RULE_FIELDS = [
    "from", "to", "source", "destination", "service", "to-interface",
    "source-translation", "destination-translation", "dynamic-destination-translation",
    "nat-type", "disabled", "description", "tag", "group-tag",
    "active-active-device-binding",
]


def _yes_no(entry: ET.Element, path: str) -> Tuple[Optional[bool], Optional[str]]:
    value = text_or_none(entry, path)
    if value is None:
        return None, None
    value = value.lower()
    if value not in {"yes", "no"}:
        raise ValueError(f"{path} must be 'yes' or 'no', found {value!r}")
    return value == "yes", value


def _resolve(resolver, values: List[str], namespace: str, scope: PANScope,
             builtins: set[str] | None = None) -> Tuple[List[str], List[str]]:
    output, unresolved = [], []
    for value in values:
        if value.lower() in (builtins or set()):
            output.append(value)
            continue
        obj = resolver.resolve(value, namespace, scope)
        if obj is None:
            unresolved.append(value)
            output.append(value)
        else:
            output.append(obj.canonical_name or value)
    return output, unresolved


class PANNatRuleExtractor:
    @staticmethod
    def extract_rule(entry: ET.Element, scope: PANScope, resolver,
                     position: str, source_index: int, prefix: str):
        name = entry.get("name")
        path = f"{prefix}/nat/rules/entry[@name='{name}']" if name else f"{prefix}/nat/rules/entry"
        evidence: Dict[str, Any] = {
            "pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
            "pan_rulebase_position": position, "pan_source_rule_index": source_index,
            "pan_source_path": path, "pan_source_entry": structured_xml_capture(entry),
        }
        if not name:
            return None, "PARSE_ERROR", evidence, ["PAN-OS NAT rule is missing its required name."]

        from_zones = member_texts(entry, "./from/member")
        to_zones = member_texts(entry, "./to/member")
        sources = member_texts(entry, "./source/member")
        destinations = member_texts(entry, "./destination/member")
        service = text_or_none(entry, "./service")
        to_interface = text_or_none(entry, "./to-interface")
        nat_type_value = text_or_none(entry, "./nat-type")
        tags = member_texts(entry, "./tag/member")
        group_tag = text_or_none(entry, "./group-tag")
        aa_binding = text_or_none(entry, "./active-active-device-binding")
        evidence.update({
            "pan_from": from_zones, "pan_to": to_zones, "pan_source": sources,
            "pan_destination": destinations, "pan_service": service,
            "pan_to_interface": to_interface, "pan_nat_type": nat_type_value,
            "pan_tags": tags, "pan_group_tag": group_tag,
            "pan_active_active_device_binding": aa_binding,
        })
        missing = [key for key, value in (("from", from_zones), ("to", to_zones),
                   ("source", sources), ("destination", destinations),
                   ("service", service)) if not value]
        if missing:
            return None, "PARTIALLY_NORMALIZED", evidence, [
                f"Missing required NAT match fields ({', '.join(missing)}); canonical rule withheld."
            ]
        try:
            disabled, disabled_raw = _yes_no(entry, "./disabled")
        except ValueError as error:
            return None, "PARSE_ERROR", evidence, [str(error)]
        evidence["pan_disabled_explicit"] = disabled_raw is not None
        if disabled_raw is not None:
            evidence["pan_disabled_value"] = disabled_raw

        canonical_sources, unresolved_sources = _resolve(resolver, sources, "address-reference", scope, {"any"})
        canonical_destinations, unresolved_destinations = _resolve(resolver, destinations, "address-reference", scope, {"any"})
        canonical_services, unresolved_services = _resolve(
            resolver, [service], "service-reference", scope,
            {"any", "application-default", "service-http", "service-https"},
        )
        translated_sources: List[str] = []
        translated_destinations: List[str] = []
        translated_port = None
        source_mode = destination_mode = None
        reasons: List[str] = []

        snat = entry.find("./source-translation")
        if snat is not None:
            evidence["pan_source_translation"] = structured_xml_capture(snat)
            families = list(snat)
            if len(families) != 1:
                reasons.append("ambiguous-source-translation")
            else:
                node = families[0]
                family = node.tag
                if family in {"dynamic-ip-and-port", "dynamic-ip"}:
                    source_mode = (NATTranslationMode.DYNAMIC_IP_AND_PORT
                                   if family == "dynamic-ip-and-port" else NATTranslationMode.POOL)
                    raw = member_texts(node, "./translated-address/member")
                    translated_sources, missing_translation = _resolve(
                        resolver, raw, "address-reference", scope
                    )
                    interface_address = node.find("./interface-address")
                    if interface_address is not None:
                        source_mode = NATTranslationMode.INTERFACE_ADDRESS
                        evidence["pan_interface_address"] = structured_xml_capture(interface_address)
                        reasons.append("interface-address-semantics")
                    fallback = node.find("./fallback")
                    if fallback is not None:
                        evidence["pan_source_translation_fallback"] = structured_xml_capture(fallback)
                        reasons.append("source-translation-fallback")
                    unknown = collect_unknown_children(node, ["translated-address", "interface-address", "fallback"])
                    if unknown:
                        evidence["pan_unknown_source_translation_fields"] = unknown
                        reasons.append("unknown-source-translation-fields")
                    if not raw and interface_address is None:
                        reasons.append("missing-translated-source")
                    if missing_translation:
                        evidence["pan_unresolved_translated_sources"] = missing_translation
                        reasons.append("unresolved-translated-source")
                elif family == "static-ip":
                    source_mode = NATTranslationMode.STATIC
                    raw = text_or_none(node, "./translated-address")
                    if raw:
                        translated_sources, missing_translation = _resolve(
                            resolver, [raw], "address-reference", scope
                        )
                        if missing_translation:
                            evidence["pan_unresolved_translated_sources"] = missing_translation
                            reasons.append("unresolved-translated-source")
                    else:
                        reasons.append("missing-translated-source")
                    try:
                        _, bidirectional = _yes_no(node, "./bi-directional")
                    except ValueError as error:
                        return None, "PARSE_ERROR", evidence, [str(error)]
                    if bidirectional is not None:
                        evidence["pan_static_ip_bi_directional"] = bidirectional
                        reasons.append("bi-directional-static-nat")
                    unknown = collect_unknown_children(node, ["translated-address", "bi-directional"])
                    if unknown:
                        evidence["pan_unknown_source_translation_fields"] = unknown
                        reasons.append("unknown-source-translation-fields")
                else:
                    reasons.append(f"unknown-source-translation:{family}")

        dnat = entry.find("./destination-translation")
        dynamic_dnat = entry.find("./dynamic-destination-translation")
        if dnat is not None and dynamic_dnat is not None:
            reasons.append("ambiguous-destination-translation")
        destination_node = dynamic_dnat if dynamic_dnat is not None else dnat
        if destination_node is not None:
            dynamic = dynamic_dnat is not None
            destination_mode = NATTranslationMode.POOL if dynamic else NATTranslationMode.STATIC
            evidence["pan_dynamic_destination_translation" if dynamic else "pan_destination_translation"] = structured_xml_capture(destination_node)
            raw = text_or_none(destination_node, "./translated-address")
            translated_port = text_or_none(destination_node, "./translated-port")
            if raw:
                translated_destinations, missing_translation = _resolve(
                    resolver, [raw], "address-reference", scope
                )
                if missing_translation:
                    evidence["pan_unresolved_translated_destinations"] = missing_translation
                    reasons.append("unresolved-translated-destination")
            else:
                reasons.append("missing-translated-destination")
            for child_name, reason in (("distribution", "dynamic-destination-distribution"),
                                       ("dns-rewrite", "destination-dns-rewrite")):
                child = destination_node.find(f"./{child_name}")
                if child is not None:
                    evidence[f"pan_destination_{child_name.replace('-', '_')}"] = structured_xml_capture(child)
                    reasons.append(reason)
            unknown = collect_unknown_children(destination_node, ["translated-address", "translated-port", "distribution", "dns-rewrite"])
            if unknown:
                evidence["pan_unknown_destination_translation_fields"] = unknown
                reasons.append("unknown-destination-translation-fields")

        if snat is None and destination_node is None:
            return None, "EXTRACT_ONLY", evidence, ["PAN-OS NAT rule has no translation block."]
        for unresolved, key, reason in (
            (unresolved_sources, "pan_unresolved_sources", "unresolved-source"),
            (unresolved_destinations, "pan_unresolved_destinations", "unresolved-destination"),
            (unresolved_services, "pan_unresolved_services", "unresolved-service"),
        ):
            if unresolved:
                evidence[key] = unresolved
                reasons.append(reason)
        for value, reason in ((to_interface, "to-interface"), (nat_type_value, "nat-type"),
                              (tags, "tag"), (group_tag, "group-tag"),
                              (aa_binding, "active-active-device-binding")):
            if value:
                reasons.append(reason)
        unknown = collect_unknown_children(entry, RULE_FIELDS)
        if unknown:
            evidence["pan_unknown_fields"] = unknown
            reasons.append("unknown-fields")
        reasons = list(dict.fromkeys(reasons))
        nat_type = NATType.TWICE if snat is not None and destination_node is not None else (
            NATType.DESTINATION if destination_node is not None else NATType.SOURCE
        )
        source_rule_id = f"palo_alto:{scope.kind}:{scope.name}:{position}:{source_index}:{name}"
        rule = IRNATRule(
            name=name, type=nat_type, source_context=f"{scope.kind}:{scope.name}",
            sequence=source_index, enabled=disabled is not True,
            from_zone=from_zones, to_zone=to_zones, source=canonical_sources,
            destination=canonical_destinations, services=canonical_services,
            service=canonical_services[0], source_translation_mode=source_mode,
            destination_translation_mode=destination_mode,
            translated_sources=translated_sources,
            translated_source=translated_sources[0] if len(translated_sources) == 1 else None,
            translated_destinations=translated_destinations,
            translated_destination=translated_destinations[0] if len(translated_destinations) == 1 else None,
            translated_port=translated_port, source_rule_id=source_rule_id,
            source_attributes=evidence, description=text_or_none(entry, "./description"),
            migration_status="PARTIALLY_NORMALIZED" if reasons else "NORMALIZED",
            review_reasons=reasons, requires_manual_review=bool(reasons),
        )
        status = "PARTIALLY_NORMALIZED" if reasons else "NORMALIZED"
        notes = [f"PAN-OS NAT rule requires review: {', '.join(reasons)}."] if reasons else []
        return rule, status, evidence, notes
