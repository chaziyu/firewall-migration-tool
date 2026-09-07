"""Scoped FortiOS 7.4.6 preservation fixes for policy/NAT dependencies.

This module intentionally fixes only source-semantics gaps in the reviewed
interface, policy, NAT, and directly referenced object scope:
- ``system interface`` / ``secondaryip`` ``ping-serv-status`` typing;
- ``firewall vip`` ``src-vip-filter`` preservation for reverse-SNAT semantics;
- context-scoped dependency resolution for preserved interface, group,
  schedule, policy-NAT, and central-SNAT references.
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


_SCOPED_REFERENCE_RULES = {
    ("system interface", "interface"): "system interface",
    ("system zone", "interface"): "system interface",
    ("firewall address", "interface"): "system interface",
    ("firewall address", "associated-interface"): "system interface",
    ("firewall address6", "interface"): "system interface",
    ("firewall address6", "associated-interface"): "system interface",
    ("firewall addrgrp", "member"): "firewall address",
    ("firewall addrgrp", "exclude-member"): "firewall address",
    ("firewall addrgrp6", "member"): "firewall address6",
    ("firewall addrgrp6", "exclude-member"): "firewall address6",
    ("firewall service group", "member"): "firewall service custom",
    ("firewall schedule group", "member"): "firewall schedule recurring",
    ("firewall vipgrp", "member"): "firewall vip",
    ("firewall vipgrp", "interface"): "system interface",
    ("firewall vipgrp6", "member"): "firewall vip6",
    ("firewall policy", "poolname"): "firewall ippool",
    ("firewall policy", "poolname6"): "firewall ippool6",
    ("firewall policy", "pcp-poolname"): "firewall ippool",
    ("firewall ippool", "associated-interface"): "system interface",
    ("firewall ippool", "arp-intf"): "system interface",
    ("firewall central-snat-map", "srcintf"): "system interface",
    ("firewall central-snat-map", "dstintf"): "system interface",
    ("firewall central-snat-map", "orig-addr"): "firewall address",
    ("firewall central-snat-map", "dst-addr"): "firewall address",
    ("firewall central-snat-map", "orig-addr6"): "firewall address6",
    ("firewall central-snat-map", "dst-addr6"): "firewall address6",
    ("firewall central-snat-map", "nat-ippool"): "firewall ippool",
    ("firewall central-snat-map", "nat-ippool6"): "firewall ippool6",
}

_SCOPED_REFERENCE_TARGETS = {
    # These fields identify actual interface objects. Do not inherit the
    # resolver's broad legacy system-interface alias that also matches zones.
    ("system interface", "interface"): {
        "system interface",
    },
    ("system zone", "interface"): {
        "system interface",
    },
    ("firewall ippool", "associated-interface"): {
        "system interface",
    },
    ("firewall ippool", "arp-intf"): {
        "system interface",
    },
    ("firewall policy", "schedule"): {
        "firewall schedule recurring",
        "firewall schedule onetime",
        "firewall schedule group",
    },
    ("firewall addrgrp", "member"): {
        "firewall address",
        "firewall addrgrp",
    },
    # FortiOS 7.4.6 documents exclude-member as an address object only, not a
    # nested address group. Keep this stricter than normal member resolution.
    ("firewall addrgrp", "exclude-member"): {
        "firewall address",
    },
    ("firewall addrgrp6", "member"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall addrgrp6", "exclude-member"): {
        "firewall address6",
    },
    ("firewall service group", "member"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall schedule group", "member"): {
        "firewall schedule recurring",
        "firewall schedule onetime",
    },
    # Preserve the existing system-zone alias and add the FortiOS 7.4.6
    # SD-WAN-zone capability for Central SNAT interface selectors.
    ("firewall central-snat-map", "srcintf"): {
        "system interface",
        "system zone",
        "system sdwan zone",
    },
    ("firewall central-snat-map", "dstintf"): {
        "system interface",
        "system zone",
        "system sdwan zone",
    },
    ("firewall central-snat-map", "orig-addr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("firewall central-snat-map", "dst-addr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("firewall central-snat-map", "orig-addr6"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall central-snat-map", "dst-addr6"): {
        "firewall address6",
        "firewall addrgrp6",
    },
}


def _preserve_source_attribute(target: Any, key: str, value: Any) -> None:
    if value is None:
        return
    if hasattr(target, "source_attributes"):
        source_attributes = dict(getattr(target, "source_attributes", {}) or {})
        source_attributes[key] = value
        target.source_attributes = source_attributes
        return
    if hasattr(target, "extra_settings"):
        extra_settings = dict(getattr(target, "extra_settings", {}) or {})
        extra_settings[key] = value
        target.extra_settings = extra_settings


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
    """Install the scoped policy/NAT preservation and relationship fixes."""

    # Parser.py resolves these model globals at runtime inside build_model().
    parser_module.FGInterface = FGInterface746
    parser_module.FGInterfaceSecondaryIP = FGInterfaceSecondaryIP746
    parser_module.FGVIP = FGVIP746
    parser_module.SECTION_EXPLICIT_FIELDS.setdefault("system interface", set()).add(
        "ping_serv_status"
    )

    # These source fields are already parsed and retained. Register their
    # relationship semantics so the extraction dependency registry can verify
    # the referenced object in the same VDOM/context instead of leaving the
    # relationship as an unvalidated string only.
    dependencies_module.REFERENCE_RULES.update(_SCOPED_REFERENCE_RULES)
    dependencies_module.REFERENCE_TARGET_SECTIONS.update(_SCOPED_REFERENCE_TARGETS)

    parser_cls = parser_module.FortiGateParser
    if not getattr(parser_cls.build_model, "_policy_nat_preservation_wrapped", False):
        original_build_model = parser_cls.build_model

        def build_model(
            self: Any,
            section_path: str,
            attributes: Dict[str, Any],
        ) -> Any:
            if section_path == "system interface":
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
                _preserve_source_attribute(virtual_ip, "src_vip_filter", setting)
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
                source_vip = source_vips.get((nat_rule.source_context, vip_name))
                if source_vip is None:
                    continue
                setting = getattr(source_vip, "src_vip_filter", None)
                _preserve_source_attribute(nat_rule, "src_vip_filter", setting)
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
