from __future__ import annotations

from typing import Any

from fwmigrate.ir.enums import NATTranslationAddressSource, NATTranslationMode
from fwmigrate.ir.nat import IRNATTranslationAddressSelection


_PATCHED = False
_DYNAMIC_IP_REVIEW = (
    "ASA dynamic NAT address-only translation is source-preserved; canonical IR has no address-only dynamic mode"
)


def _interface_pat_selection(source: Any) -> IRNATTranslationAddressSelection:
    return IRNATTranslationAddressSelection(
        address_source=NATTranslationAddressSource.INTERFACE_ADDRESS,
        interface=source.destination_interface or source.source_interface,
    )


def apply_remaining_nat_fixes(ir: Any, config: Any) -> Any:
    """Apply source-preserving dynamic NAT semantics to canonical IR."""
    source_by_key = {
        (rule.source_context, rule.name): rule for rule in config.nat_rules
    }
    for rule in ir.nat_rules:
        source = source_by_key.get((rule.source_context, rule.name))
        if source is None or source.source_mode != "dynamic":
            continue
        if source.mapped_source_mode == "interface":
            rule.source_translation_mode = NATTranslationMode.DYNAMIC_IP_AND_PORT
            rule.source_translation_address_selection = _interface_pat_selection(source)
            rule.translated_sources = [
                value for value in rule.translated_sources
                if value.casefold() != "interface"
            ]
            rule.source_attributes["asa_translation_semantics"] = "dynamic-pat-interface"
        elif source.mapped_source_mode == "pat_pool":
            rule.source_translation_mode = NATTranslationMode.DYNAMIC_IP_AND_PORT
            rule.source_attributes["asa_translation_semantics"] = "dynamic-pat-pool"
        else:
            rule.source_translation_mode = NATTranslationMode.DYNAMIC_IP
            rule.source_attributes["asa_translation_semantics"] = "dynamic-nat"
            rule.review_reasons = [
                reason for reason in rule.review_reasons
                if reason != _DYNAMIC_IP_REVIEW
            ]
            if not source.requires_manual_review and not rule.review_reasons:
                rule.requires_manual_review = False
                rule.migration_status = "NORMALIZED"
        if source.source_attributes.get("interface_pat_fallback"):
            if rule.source_translation_fallback is not None:
                rule.source_translation_fallback.mode = NATTranslationMode.DYNAMIC_IP_AND_PORT
                if rule.source_translation_fallback.address_selection is None:
                    rule.source_translation_fallback.address_selection = _interface_pat_selection(source)
            rule.source_attributes["fallback_translation_semantics"] = "dynamic-pat-interface"
    return ir


def _wrap_transform_to_ir(original: Any):
    def transform(self: Any):
        return apply_remaining_nat_fixes(original(self), self.config)

    return transform


def apply_cisco_asa_remaining_fixes(parser_cls: Any) -> None:
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True
    parser_cls.transform_to_ir = _wrap_transform_to_ir(parser_cls.transform_to_ir)
