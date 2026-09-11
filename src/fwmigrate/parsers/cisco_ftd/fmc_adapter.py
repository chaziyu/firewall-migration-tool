from __future__ import annotations

from typing import Any, List, Tuple

from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.ir.enums import NATTranslationMode
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
        ir = IRConfig(metadata=IRMetadata(
            source_vendor="cisco_ftd",
            source_product="Cisco Secure Firewall Management Center / FTD",
            input_type="fmc-rest-export",
            source_context=self.context,
        ))
        self._parse_objects(ir)
        self._parse_access_policies(ir)
        self._parse_nat_policies(ir)
        self._parse_pbr_policies(ir)
        ir.addresses.extend(self._synthetic_addresses.values())
        ir.services.extend(self._synthetic_services.values())

        for policy in ir.policies:
            raw = policy.source_extra_settings.get("fmc_rule")
            if not isinstance(raw, dict):
                continue

            # FMC source-port matching is independent from destination service
            # matching. Never turn a source-port criterion into a destination
            # service. Preserve it until canonical policy IR grows an
            # independent source-port criterion.
            source_ports = raw.get("sourcePorts")
            destination_ports = raw.get("destinationPorts")
            if source_ports:
                policy.source_extra_settings["fmc_source_ports"] = source_ports
                if not destination_ports:
                    policy.service = [IR_KEYWORD_ANY]
                    policy.source_service_references = [IR_KEYWORD_ANY]
                reason = (
                    "FMC source-port match is source-preserved; canonical policy IR "
                    "has no independent source-port criterion"
                )
                if reason not in policy.review_reasons:
                    policy.review_reasons.append(reason)
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"

            # User/identity matching depends on target identity-provider and
            # authentication semantics. Keep the references, but do not claim
            # automatic target equivalence merely because the names resolved.
            if policy.source_users or policy.source_user_groups:
                policy.identity_dependency_review = True
                reason = (
                    "FMC user/identity criteria require target identity-provider validation"
                )
                if reason not in policy.review_reasons:
                    policy.review_reasons.append(reason)
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"

        for rule in ir.nat_rules:
            raw = rule.source_attributes.get("fmc_nat_rule")
            if isinstance(raw, dict) and raw.get("id"):
                rule.source_attributes["fmc_rule_uuid"] = raw["id"]

            # DYNAMIC_IP is represented exactly in canonical IR, but the
            # current target generators do not all emit this mode safely.
            if rule.source_translation_mode == NATTranslationMode.DYNAMIC_IP:
                reason = (
                    "Address-only dynamic NAT is canonicalized, but target-generator "
                    "support must be validated"
                )
                if reason not in rule.review_reasons:
                    rule.review_reasons.append(reason)
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"

        if self._unresolved:
            ir.generation_safe = False
            for item in self._unresolved:
                owner = item.get("owner") if isinstance(item, dict) else None
                field = item.get("field") if isinstance(item, dict) else None
                reason = f"Unresolved FMC reference: {owner or 'unknown'} / {field or 'unknown'}"
                if reason not in ir.generation_blocking_reasons:
                    ir.generation_blocking_reasons.append(reason)

        if any(item.requires_manual_review for item in [*ir.policies, *ir.nat_rules]):
            ir.generation_safe = False
            reason = "FMC policy/NAT semantics require manual target validation"
            if reason not in ir.generation_blocking_reasons:
                ir.generation_blocking_reasons.append(reason)

        return ir


__all__ = ["CiscoFMCBundleParser", "FMC_BUNDLE_FORMAT", "is_fmc_bundle"]
