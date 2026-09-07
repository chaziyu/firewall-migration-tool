from __future__ import annotations

from typing import Any

from fwmigrate.ir.enums import NATTranslationMode


_PATCHED = False
_DYNAMIC_IP_REVIEW = (
    "ASA dynamic NAT address-only translation is source-preserved; canonical IR has no address-only dynamic mode"
)


def _wrap_transform_to_ir(original: Any):
    def transform(self: Any):
        ir = original(self)
        source_by_key = {
            (rule.source_context, rule.name): rule
            for rule in self.config.nat_rules
        }
        for rule in ir.nat_rules:
            source = source_by_key.get((rule.source_context, rule.name))
            if source is None or source.source_mode != "dynamic":
                continue
            if source.mapped_source_mode in {"interface", "pat_pool"}:
                continue

            # Dynamic NAT translates only the source address.  It is distinct
            # from PAT, where the source port is also translated.
            rule.source_translation_mode = NATTranslationMode.DYNAMIC_IP
            rule.source_attributes["asa_translation_semantics"] = "dynamic-nat"
            rule.review_reasons = [reason for reason in rule.review_reasons if reason != _DYNAMIC_IP_REVIEW]

            # PR #40 had to mark this partial because the canonical enum did not
            # yet have an address-only dynamic mode.  Once the mode exists, that
            # review state is no longer necessary unless another source semantic
            # (for example interface PAT fallback) still requires review.
            if not source.requires_manual_review and not rule.review_reasons:
                rule.requires_manual_review = False
                rule.migration_status = "NORMALIZED"

        return ir

    return transform


def apply_cisco_asa_remaining_fixes(parser_cls: Any) -> None:
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True
    parser_cls.transform_to_ir = _wrap_transform_to_ir(parser_cls.transform_to_ir)
