"""Target capability checks for fully captured FortiGate NAT semantics."""

from __future__ import annotations

from typing import Any

from fwmigrate.capabilities.schema import (
    CapabilityAnalysisResult,
    CapabilityIssue,
    CapabilityStatus,
)
from fwmigrate.generators.nat_capabilities import nat_capabilities
from fwmigrate.ir import IRConfig


def _append_issue(
    issues: list[CapabilityIssue],
    *,
    feature: str,
    reason: str,
    object_type: str,
    object_id: str,
    target_vendor: str,
) -> None:
    key = (feature, object_type, object_id, target_vendor, reason)
    if any(
        (item.feature, item.object_type, item.object_id, item.target_vendor, item.reason) == key
        for item in issues
    ):
        return
    issues.append(
        CapabilityIssue(
            feature=feature,
            status=CapabilityStatus.UNSUPPORTED,
            reason=reason,
            object_type=object_type,
            object_id=object_id,
            target_vendor=target_vendor,
            blocks_generation=True,
        )
    )


def _src_vip_filter_enabled(obj: Any) -> bool:
    source_attributes = getattr(obj, "source_attributes", {}) or {}
    extra_settings = getattr(obj, "extra_settings", {}) or {}
    value = source_attributes.get(
        "src_vip_filter_enabled",
        extra_settings.get("src_vip_filter_enabled"),
    )
    if value is not None:
        return bool(value)
    raw = source_attributes.get("src_vip_filter", extra_settings.get("src_vip_filter"))
    return raw == "enable"


def _source_incomplete(obj: Any) -> bool:
    return bool(
        getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED"
        or getattr(obj, "requires_manual_review", False)
        or getattr(obj, "review_reasons", [])
    )


def _add_fortigate_nat_capability_issues(
    ir_config: IRConfig,
    target_vendor: str,
    issues: list[CapabilityIssue],
) -> None:
    caps = nat_capabilities(target_vendor)

    for pool in getattr(ir_config, "ip_pools", []):
        object_id = str(pool.name)
        if _source_incomplete(pool):
            _append_issue(
                issues,
                feature="ip-pool-source-completeness",
                reason="Source IP-pool semantics are incomplete or require manual review; target generation is withheld.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
            continue
        if getattr(pool, "address_family", "ipv4") != "ipv4":
            if getattr(pool, "nat46", None) and not caps.nat46:
                _append_issue(
                    issues,
                    feature="nat46-pool",
                    reason="Target platform does not support NAT46 IP-pool semantics.",
                    object_type="IPPool",
                    object_id=object_id,
                    target_vendor=target_vendor,
                )
            continue

        pool_type = getattr(pool, "pool_type", None)
        if pool_type == "port-block-allocation" and not caps.pba:
            _append_issue(
                issues,
                feature="port-block-allocation",
                reason="Target platform does not support FortiGate port-block-allocation IP pools.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
        if pool_type == "cgn-resource-allocation" and not caps.cgn:
            _append_issue(
                issues,
                feature="cgn-resource-allocation",
                reason="Target platform does not support FortiGate CGN resource-allocation IP pools.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
        if pool_type == "fixed-port-range" and not caps.source_port_policy:
            _append_issue(
                issues,
                feature="fixed-port-range",
                reason="Target platform does not support FortiGate fixed-port-range IP-pool semantics.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
        if (
            getattr(pool, "block_size", None) is not None
            or getattr(pool, "blocks_per_user", None) is not None
            or getattr(pool, "pba_timeout", None) is not None
            or getattr(pool, "pba_interim_log", None) is not None
            or getattr(pool, "ports_per_user", None) is not None
            or getattr(pool, "privileged_port_use_pba", None) is not None
        ) and not caps.pba:
            _append_issue(
                issues,
                feature="pba-settings",
                reason="Target platform does not support FortiGate PBA IP-pool settings.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
        if any(
            getattr(pool, field, None) is not None
            for field in (
                "cgn_block_size",
                "cgn_client_start_ip",
                "cgn_client_end_ip",
                "cgn_client_ipv6_shift",
                "cgn_fixed_allocation",
                "cgn_overload",
                "cgn_port_start",
                "cgn_port_end",
                "cgn_spa",
            )
        ) and not caps.cgn:
            _append_issue(
                issues,
                feature="cgn-settings",
                reason="Target platform does not support FortiGate CGN IP-pool settings.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
        if getattr(pool, "nat64", None) and not caps.nat64:
            _append_issue(
                issues,
                feature="nat64-pool",
                reason="Target platform does not support NAT64 IP-pool semantics.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )
        if (
            getattr(pool, "excluded_ips", [])
            or getattr(pool, "permit_any_host", None)
        ) and target_vendor != "fortigate":
            _append_issue(
                issues,
                feature="fortigate-pool-selection",
                reason="Target platform cannot reproduce FortiGate IP-pool exclusions/full-cone selection exactly.",
                object_type="IPPool",
                object_id=object_id,
                target_vendor=target_vendor,
            )

    for vip in getattr(ir_config, "virtual_ips", []):
        if _src_vip_filter_enabled(vip) and target_vendor != "fortigate":
            _append_issue(
                issues,
                feature="src-vip-filter",
                reason="Target platform has no proven equivalent for FortiGate src-vip-filter reverse-SNAT behavior.",
                object_type="VirtualIP",
                object_id=str(vip.name),
                target_vendor=target_vendor,
            )

    for group in getattr(ir_config, "virtual_ip_groups", []):
        if _source_incomplete(group):
            _append_issue(
                issues,
                feature="vip-group-source-completeness",
                reason="Source VIP-group semantics are incomplete or require manual review; target generation is withheld.",
                object_type="VirtualIPGroup",
                object_id=str(group.name),
                target_vendor=target_vendor,
            )
            continue
        if target_vendor != "fortigate":
            _append_issue(
                issues,
                feature="vip-group",
                reason="Target platform has no proven native FortiGate VIP-group equivalent.",
                object_type="VirtualIPGroup",
                object_id=str(group.name),
                target_vendor=target_vendor,
            )


def install_fortigate_nat_capability_remediation(analyzer_module: Any) -> None:
    analyzer_cls = analyzer_module.CapabilityAnalyzer
    original = analyzer_cls.analyze
    if getattr(original, "_fortigate_nat_remediation", False):
        return

    def analyze(
        self: Any,
        ir_config: IRConfig,
        target_vendor: str | None = None,
    ) -> CapabilityAnalysisResult:
        result = original(self, ir_config, target_vendor)
        if not isinstance(result, CapabilityAnalysisResult):
            result = CapabilityAnalysisResult(list(result))
        vendor = target_vendor or (
            self.target_profile.vendor_id if getattr(self, "target_profile", None) else ""
        )
        issues = list(result.issues)
        _add_fortigate_nat_capability_issues(ir_config, vendor, issues)
        return CapabilityAnalysisResult(issues)

    analyze._fortigate_nat_remediation = True
    analyzer_cls.analyze = analyze


__all__ = ["install_fortigate_nat_capability_remediation"]
