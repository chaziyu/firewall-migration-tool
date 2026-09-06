"""Scoped FortiOS 7.4.6 preservation fixes for policy/NAT dependencies.

This module intentionally fixes only three source-semantics gaps:
- ``system interface`` / ``secondaryip`` ``ping-serv-status`` typing;
- ``firewall vip`` ``src-vip-filter`` preservation for reverse-SNAT semantics;
- ``firewall policy`` references to one-time schedules.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import model_validator

from fwmigrate.parsers.fortigate.model import (
    FGInterface as _FGInterface,
    FGInterfaceSecondaryIP as _FGInterfaceSecondaryIP,
    FGVIP as _FGVIP,
    _preserve_malformed_int_fields,
)


class FGInterfaceSecondaryIP746(_FGInterfaceSecondaryIP):
    """FortiOS 7.4.6 secondary-IP fields required for exact source retention."""

    ping_serv_status: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_ping_serv_status(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"ping_serv_status"})


class FGInterface746(_FGInterface):
    """FortiOS 7.4.6 interface fields required for exact source retention."""

    ping_serv_status: Optional[int] = None


class FGVIP746(_FGVIP):
    """VIP source field controlling reverse-SNAT source-filter semantics."""

    src_vip_filter: Optional[str] = None


def _preserve_source_attribute(target: Any, key: str, value: Any) -> None:
    if value is None or not hasattr(target, "source_attributes"):
        return
    source_attributes = dict(getattr(target, "source_attributes", {}) or {})
    source_attributes[key] = value
    target.source_attributes = source_attributes


def _mark_manual_review(target: Any, reason: str) -> None:
    if hasattr(target, "review_reasons"):
        review_reasons = list(getattr(target, "review_reasons", []) or [])
        if reason not in review_reasons:
            review_reasons.append(reason)
        target.review_reasons = review_reasons
    if hasattr(target, "requires_manual_review"):
        target.requires_manual_review = True
    if hasattr(target, "migration_status"):
        target.migration_status = "PARTIALLY_NORMALIZED"


def install_policy_nat_preservation_extensions(
    parser_module: Any,
    transformer_module: Any,
    dependencies_module: Any,
) -> None:
    """Install only the three scoped policy/NAT preservation fixes."""

    # Parser.py resolves these model globals at runtime inside build_model().
    parser_module.FGInterface = FGInterface746
    parser_module.FGInterfaceSecondaryIP = FGInterfaceSecondaryIP746
    parser_module.FGVIP = FGVIP746
    parser_module.SECTION_EXPLICIT_FIELDS.setdefault("system interface", set()).add(
        "ping_serv_status"
    )

    # Normal firewall policies can reference either schedule family. Keep the
    # existing expected-type label while broadening only its valid target set.
    dependencies_module.REFERENCE_TARGET_SECTIONS[(
        "firewall policy",
        "schedule",
    )] = {
        "firewall schedule recurring",
        "firewall schedule onetime",
    }

    parser_cls = parser_module.FortiGateParser
    if not getattr(parser_cls.build_model, "_policy_nat_preservation_wrapped", False):
        original_build_model = parser_cls.build_model

        def build_model(
            self: Any,
            section_path: str,
            attributes: Dict[str, Any],
        ) -> Any:
            if section_path == "system interface":
                # FortiOS 7.4.6 uses the exact CLI key ``ping-serv-status`` and
                # documents it as an integer. Preserve malformed input through
                # the parser's normal ``unparsed_*`` source-evidence path.
                self._normalize_optional_int(attributes, "ping_serv_status")
            return original_build_model(self, section_path, attributes)

        build_model._policy_nat_preservation_wrapped = True
        parser_cls.build_model = build_model

    transformer_cls = transformer_module.FGToIRTransformer

    if not getattr(
        transformer_cls._transform_virtual_ips,
        "_policy_nat_preservation_wrapped",
        False,
    ):
        original_transform_virtual_ips = transformer_cls._transform_virtual_ips

        def _transform_virtual_ips(self: Any) -> None:
            original_transform_virtual_ips(self)
            source_vips = {
                (vip.source_context, vip.name): vip
                for vip in self.fg.vips
            }
            for virtual_ip in self.ir.virtual_ips:
                source_vip = source_vips.get(
                    (virtual_ip.source_context, virtual_ip.name)
                )
                if source_vip is None:
                    continue
                setting = getattr(source_vip, "src_vip_filter", None)
                _preserve_source_attribute(
                    virtual_ip,
                    "src_vip_filter",
                    setting,
                )
                if setting == "enable":
                    _mark_manual_review(
                        virtual_ip,
                        (
                            f"VIP '{source_vip.name}' enables src-vip-filter; "
                            "FortiGate reverse-SNAT source filtering is source-specific."
                        ),
                    )

        _transform_virtual_ips._policy_nat_preservation_wrapped = True
        transformer_cls._transform_virtual_ips = _transform_virtual_ips

    if not getattr(
        transformer_cls._transform_nat,
        "_policy_nat_preservation_wrapped",
        False,
    ):
        original_transform_nat = transformer_cls._transform_nat

        def _transform_nat(self: Any) -> None:
            original_transform_nat(self)
            source_vips = {
                (vip.source_context, vip.name): vip
                for vip in self.fg.vips
            }
            for nat_rule in self.ir.nat_rules:
                vip_name = getattr(nat_rule, "source_vip_reference", None)
                if not vip_name:
                    continue
                source_vip = source_vips.get(
                    (nat_rule.source_context, vip_name)
                )
                if source_vip is None:
                    continue
                setting = getattr(source_vip, "src_vip_filter", None)
                _preserve_source_attribute(
                    nat_rule,
                    "src_vip_filter",
                    setting,
                )
                if setting == "enable":
                    _mark_manual_review(
                        nat_rule,
                        (
                            f"VIP '{source_vip.name}' enables src-vip-filter; "
                            "reverse-SNAT source filtering must remain explicit."
                        ),
                    )

        _transform_nat._policy_nat_preservation_wrapped = True
        transformer_cls._transform_nat = _transform_nat
