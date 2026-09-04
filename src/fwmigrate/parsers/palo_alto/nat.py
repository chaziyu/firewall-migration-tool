"""Structured, direct-path PAN-OS NAT extraction."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import ipaddress
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATTranslationMode, NATType
from .source_model import PANScope, pan_scope_identity
from .predefined_services import PAN_RULE_SERVICE_BUILTINS
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none

RULE_FIELDS = [
    "from", "to", "source", "destination", "service", "to-interface",
    "source-translation", "destination-translation", "dynamic-destination-translation",
    "nat-type", "disabled", "description", "tag", "group-tag",
    "active-active-device-binding",
]


@dataclass(frozen=True)
class PANNATTranslationValue:
    """Classification of one PAN-OS translated-address value."""

    value: str
    classification: str
    resolved_value: Optional[str] = None
    reason: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "classification": self.classification,
            "resolved_value": self.resolved_value,
            "reason": self.reason,
        }


def parse_pan_nat_translation_value(
    value: str, resolver=None, scope: Optional[PANScope] = None
) -> PANNATTranslationValue:
    """Classify a PAN translated-address as literal, object, or invalid.

    PAN-OS translation fields accept literal addresses/ranges as well as
    address-object names.  Address-object resolution is deliberately attempted
    only after strict literal parsing, so a valid literal is never reported as
    an unresolved object reference.
    """
    raw = (value or "").strip()
    if not raw:
        return PANNATTranslationValue(raw, "invalid", reason="empty translated-address value")
    try:
        ipaddress.ip_address(raw)
        return PANNATTranslationValue(raw, "literal-host", resolved_value=raw)
    except ValueError:
        pass
    try:
        ipaddress.ip_network(raw, strict=False)
        return PANNATTranslationValue(raw, "literal-prefix", resolved_value=raw)
    except ValueError:
        pass
    if resolver is not None and scope is not None:
        resolved = resolver.resolve(raw, "address-reference", scope)
        if resolved is not None:
            return PANNATTranslationValue(
                raw, "object-reference", resolved_value=resolved.canonical_name or raw
            )
    if raw.count("-") == 1:
        start, end = (part.strip() for part in raw.split("-", 1))
        try:
            first = ipaddress.ip_address(start)
            last = ipaddress.ip_address(end)
            if first.version != last.version or int(first) > int(last):
                raise ValueError("range endpoints must be same-family and ordered")
            return PANNATTranslationValue(raw, "literal-range", resolved_value=raw)
        except ValueError as error:
            return PANNATTranslationValue(raw, "invalid", reason=str(error))
    return PANNATTranslationValue(
        raw, "unresolved-reference", reason="value is neither a valid literal nor a resolved address object"
    )


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


def _translation_values(resolver, values: List[str], scope: PANScope) -> tuple[List[str], List[str], List[str], List[dict]]:
    translated: List[str] = []
    unresolved: List[str] = []
    invalid: List[str] = []
    classifications: List[dict] = []
    for value in values:
        classified = parse_pan_nat_translation_value(value, resolver, scope)
        classifications.append(classified.as_dict())
        if classified.classification == "invalid":
            invalid.append(value)
            continue
        if classified.classification == "unresolved-reference":
            unresolved.append(value)
            translated.append(value)
        else:
            translated.append(classified.resolved_value or value)
    return translated, unresolved, invalid, classifications


def _translation_members(node: Optional[ET.Element], path: str = "./translated-address") -> List[str]:
    if node is None:
        return []
    values = member_texts(node, f"{path}/member")
    if values:
        return values
    scalar = text_or_none(node, path)
    return [scalar] if scalar else []


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
        if scope.device_serial:
            evidence["pan_device_serial"] = scope.device_serial
        if not name:
            return None, "PARSE_ERROR", evidence, ["PAN-OS NAT rule is missing its required name."]

        from_zones = member_texts(entry, "./from/member")
        to_zones = member_texts(entry, "./to/member")
        sources = member_texts(entry, "./source/member")
        destinations = member_texts(entry, "./destination/member")
        service = text_or_none(entry, "./service")
        to_interface = text_or_none(entry, "./to-interface")
        nat_type_node = entry.find("./nat-type")
        nat_type_value = text_or_none(entry, "./nat-type")
        if nat_type_value is None and nat_type_node is not None and len(nat_type_node) == 1:
            nat_type_value = next(iter(nat_type_node)).tag
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
        if nat_type_value is not None:
            nat_family = nat_type_value.strip().lower()
            evidence["pan_nat_family"] = nat_family if nat_family in {"ipv4", "nat64", "nptv6"} else "unknown"
            if nat_type_node is not None and not text_or_none(entry, "./nat-type"):
                evidence["pan_nat_type_settings"] = structured_xml_capture(nat_type_node)
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
            PAN_RULE_SERVICE_BUILTINS,
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
                evidence["pan_source_translation_mode"] = family
                if family in {"dynamic-ip-and-port", "dynamic-ip"}:
                    source_mode = (NATTranslationMode.DYNAMIC_IP_AND_PORT
                                   if family == "dynamic-ip-and-port" else NATTranslationMode.POOL)
                    raw = _translation_members(node)
                    translated_sources, missing_translation, invalid_translation, classifications = _translation_values(
                        resolver, raw, scope
                    )
                    evidence["pan_translated_source_values"] = classifications
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
                    if invalid_translation:
                        evidence["pan_invalid_translated_sources"] = invalid_translation
                        reasons.append("invalid-translated-source")
                    if family == "persistent-dynamic-ip-and-port":
                        reasons.append("persistent-dipp")
                elif family == "persistent-dynamic-ip-and-port":
                    source_mode = NATTranslationMode.DYNAMIC_IP_AND_PORT
                    raw = _translation_members(node)
                    translated_sources, missing_translation, invalid_translation, classifications = _translation_values(
                        resolver, raw, scope
                    )
                    evidence["pan_translated_source_values"] = classifications
                    if missing_translation:
                        evidence["pan_unresolved_translated_sources"] = missing_translation
                        reasons.append("unresolved-translated-source")
                    if invalid_translation:
                        evidence["pan_invalid_translated_sources"] = invalid_translation
                        reasons.append("invalid-translated-source")
                    reasons.append("persistent-dipp")
                elif family == "static-ip":
                    source_mode = NATTranslationMode.STATIC
                    raw = text_or_none(node, "./translated-address")
                    if raw:
                        translated_sources, missing_translation, invalid_translation, classifications = _translation_values(
                            resolver, [raw], scope
                        )
                        evidence["pan_translated_source_values"] = classifications
                        if missing_translation:
                            evidence["pan_unresolved_translated_sources"] = missing_translation
                            reasons.append("unresolved-translated-source")
                        if invalid_translation:
                            evidence["pan_invalid_translated_sources"] = invalid_translation
                            reasons.append("invalid-translated-source")
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
            raw_values = _translation_members(destination_node)
            translated_port = text_or_none(destination_node, "./translated-port")
            if raw_values:
                translated_destinations, missing_translation, invalid_translation, classifications = _translation_values(
                    resolver, raw_values, scope
                )
                evidence["pan_translated_destination_values"] = classifications
                if missing_translation:
                    evidence["pan_unresolved_translated_destinations"] = missing_translation
                    reasons.append("unresolved-translated-destination")
                if invalid_translation:
                    evidence["pan_invalid_translated_destinations"] = invalid_translation
                    reasons.append("invalid-translated-destination")
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
        for value, reason in ((to_interface, "to-interface"),
                              (tags, "tag"), (group_tag, "group-tag"),
                              (aa_binding, "active-active-device-binding")):
            if value:
                reasons.append(reason)
        if nat_type_value and nat_type_value.strip().lower() in {"nat64", "nptv6"}:
            # PAN's address-family operation is not the same dimension as
            # source/destination/twice NAT.  Preserve the family as evidence
            # and withhold the rule from a falsely equivalent IPv4 target.
            reasons.append(f"{nat_type_value.strip().lower()}-source-semantics")
        elif nat_type_value and nat_type_value.strip().lower() not in {"ipv4"}:
            reasons.append("unknown-nat-family")
        unknown = collect_unknown_children(entry, RULE_FIELDS)
        if unknown:
            evidence["pan_unknown_fields"] = unknown
            reasons.append("unknown-fields")
        reasons = list(dict.fromkeys(reasons))
        nat_type = NATType.TWICE if snat is not None and destination_node is not None else (
            NATType.DESTINATION if destination_node is not None else NATType.SOURCE
        )
        source_rule_id = f"palo_alto:{pan_scope_identity(scope)}:{position}:{source_index}:{name}"
        rule = IRNATRule(
            name=name, type=nat_type, source_context=pan_scope_identity(scope),
            sequence=source_index, enabled=disabled is not True,
            from_zone=from_zones, to_zone=to_zones,
            source_to_interfaces=[to_interface] if to_interface else [],
            source=canonical_sources,
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
