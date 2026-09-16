from __future__ import annotations

from typing import Any, List, Tuple

from fwmigrate.ir import IRConfig
from fwmigrate.parsers.cisco_ftd.fmc_bundle import (
    CiscoFMCBundleParser as _RawCiscoFMCBundleParser,
    FMC_BUNDLE_FORMAT,
    is_fmc_bundle,
)


class CiscoFMCBundleParser(_RawCiscoFMCBundleParser):
    """Production FMC bundle adapter with canonical safety gates.

    The raw parser owns FMC REST payload decoding. This wrapper owns the
    target-neutral safety decisions that must not be guessed from FMC fields.
    """

    @staticmethod
    def _fail_closed_refs(result: Tuple[List[str], bool]) -> Tuple[List[str], bool]:
        values, unresolved = result
        if unresolved and values == [IR_KEYWORD_ANY]:
            return [], True
        return values, unresolved

    @staticmethod
    def _coerce_nat_order_index(value: Any) -> int | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip()
            if text and text.lstrip("+-").isdigit():
                return int(text)
        return None

    @classmethod
    def _order_values_conflict(cls, rules: List[Any], key: str) -> bool:
        values = []
        for position, rule in enumerate(rules, 1):
            value = cls._coerce_nat_order_index(rule.source_attributes.get(key))
            if value is not None:
                values.append((position, value))
        if len(values) < 2:
            return False
        numeric = [value for _, value in values]
        return len(set(numeric)) != len(numeric) or any(
            current <= previous for previous, current in zip(numeric, numeric[1:])
        )

    @classmethod
    def _mark_nat_order_conflicts(cls, rules: List[Any]) -> None:
        grouped: dict[tuple[Any, Any], List[Any]] = {}
        for rule in rules:
            key = (
                rule.source_attributes.get("fmc_policy_id"),
                rule.source_attributes.get("fmc_nat_section"),
            )
            grouped.setdefault(key, []).append(rule)

        reason = (
            "FMC NAT ordering metadata conflicts with bundle traversal order; "
            "effective order is source-preserved and requires review"
        )
        for section_rules in grouped.values():
            for position, rule in enumerate(section_rules, 1):
                rule.source_attributes["fmc_bundle_position"] = position

            conflict = cls._order_values_conflict(section_rules, "fmc_target_index") or cls._order_values_conflict(
                section_rules, "fmc_source_index"
            )
            for rule in section_rules:
                rule.source_attributes["fmc_order_consistent"] = not conflict
                if not conflict:
                    continue
                rule.source_attributes["fmc_order_review_reason"] = reason
                if reason not in rule.review_reasons:
                    rule.review_reasons.append(reason)
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"

    def _network_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        return self._fail_closed_refs(
            super()._network_refs(container, owner=owner, field=field)
        )

    def _zone_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        return self._fail_closed_refs(
            super()._zone_refs(container, owner=owner, field=field)
        )

    def _service_refs(self, container: Any, *, owner: str, field: str) -> Tuple[List[str], bool]:
        return self._fail_closed_refs(
            super()._service_refs(container, owner=owner, field=field)
        )

    def parse(self) -> IRConfig:
        from .transformer import FMCToIRTransformer

        return FMCToIRTransformer(self).transform()


__all__ = ["CiscoFMCBundleParser", "FMC_BUNDLE_FORMAT", "is_fmc_bundle"]
