"""Focused FortiGate target-generation support for audited NAT resources."""

from __future__ import annotations

from typing import Any, Iterable

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.generators.target_helpers import is_generation_safe_object
from fwmigrate.ir.extension_models import get_object_extension_value


_ADVANCED_POOL_TYPES = {
    "fixed-port-range",
    "port-block-allocation",
    "cgn-resource-allocation",
}

_POOL_FIELD_MAP = (
    ("source-startip", "source_start_ip", False),
    ("source-endip", "source_end_ip", False),
    ("startport", "start_port", False),
    ("endport", "end_port", False),
    ("arp-intf", "arp_interface", True),
    ("block-size", "block_size", False),
    ("num-blocks-per-user", "blocks_per_user", False),
    ("pba-timeout", "pba_timeout", False),
    ("pba-interim-log", "pba_interim_log", False),
    ("port-per-user", "ports_per_user", False),
    ("client-prefix-length", "client_prefix_length", False),
    ("tcp-session-quota", "tcp_session_quota", False),
    ("udp-session-quota", "udp_session_quota", False),
    ("icmp-session-quota", "icmp_session_quota", False),
    ("cgn-block-size", "cgn_block_size", False),
    ("cgn-client-startip", "cgn_client_start_ip", False),
    ("cgn-client-endip", "cgn_client_end_ip", False),
    ("cgn-client-ipv6shift", "cgn_client_ipv6_shift", False),
    ("cgn-port-start", "cgn_port_start", False),
    ("cgn-port-end", "cgn_port_end", False),
    ("utilization-alarm-clear", "utilization_alarm_clear", False),
    ("utilization-alarm-raise", "utilization_alarm_raise", False),
)

_POOL_BOOL_FIELD_MAP = (
    ("arp-reply", "arp_reply"),
    ("permit-any-host", "permit_any_host"),
    ("privileged-port-use-pba", "privileged_port_use_pba"),
    ("nat64", "nat64"),
    ("add-nat64-route", "add_nat64_route"),
    ("subnet-broadcast-in-ippool", "include_subnet_broadcast"),
    ("cgn-fixedalloc", "cgn_fixed_allocation"),
    ("cgn-overload", "cgn_overload"),
    ("cgn-spa", "cgn_spa"),
)


def _quoted(value: Any) -> str:
    return '"' + str(value).replace('"', '\\"') + '"'


def _explicit(pool: Any, source_name: str) -> bool:
    explicit = set(getattr(pool, "source_explicit_fields", []) or [])
    normalized = source_name.replace("-", "_")
    return source_name in explicit or normalized in explicit


def _advanced_pool(pool: Any) -> bool:
    if getattr(pool, "pool_type", None) in _ADVANCED_POOL_TYPES:
        return True
    if getattr(pool, "excluded_ips", []):
        return True
    return any(
        getattr(pool, attr, None) is not None and _explicit(pool, source_name)
        for source_name, attr in _POOL_BOOL_FIELD_MAP
        if source_name != "arp-reply"
    ) or any(
        getattr(pool, attr, None) is not None and _explicit(pool, source_name)
        for source_name, attr, _ in _POOL_FIELD_MAP
    )


def _emit_ipv4_pool(pool: Any) -> list[str]:
    lines = [f"    edit {_quoted(pool.name)}"]
    if getattr(pool, "pool_type", None):
        lines.append(f"        set type {pool.pool_type}")
    if getattr(pool, "start_ip", None):
        lines.append(f"        set startip {pool.start_ip}")
    if getattr(pool, "end_ip", None):
        lines.append(f"        set endip {pool.end_ip}")
    if getattr(pool, "associated_interface", None):
        lines.append(f"        set associated-interface {_quoted(pool.associated_interface)}")
    for source_name, attr, quote in _POOL_FIELD_MAP:
        value = getattr(pool, attr, None)
        if value is None or not _explicit(pool, source_name):
            continue
        rendered = _quoted(value) if quote else str(value)
        lines.append(f"        set {source_name} {rendered}")
    for source_name, attr in _POOL_BOOL_FIELD_MAP:
        value = getattr(pool, attr, None)
        if value is None or not _explicit(pool, source_name):
            continue
        lines.append(f"        set {source_name} {'enable' if value else 'disable'}")
    if getattr(pool, "excluded_ips", []) and _explicit(pool, "exclude-ip"):
        values = " ".join(_quoted(value) for value in pool.excluded_ips)
        lines.append(f"        set exclude-ip {values}")
    if getattr(pool, "description", None):
        lines.append(f"        set comments {_quoted(pool.description)}")
    lines.append("    next")
    return lines


def _emit_ipv6_pool(pool: Any) -> list[str]:
    lines = [f"    edit {_quoted(pool.name)}"]
    if getattr(pool, "start_ip", None):
        lines.append(f"        set startip {pool.start_ip}")
    if getattr(pool, "end_ip", None):
        lines.append(f"        set endip {pool.end_ip}")
    nat46 = get_object_extension_value(pool, "nat46")
    add_nat46_route = get_object_extension_value(pool, "add_nat46_route")
    if nat46 is not None and _explicit(pool, "nat46"):
        lines.append(f"        set nat46 {'enable' if nat46 else 'disable'}")
    if add_nat46_route is not None and _explicit(pool, "add-nat46-route"):
        lines.append(
            f"        set add-nat46-route {'enable' if add_nat46_route else 'disable'}"
        )
    if getattr(pool, "description", None):
        lines.append(f"        set comments {_quoted(pool.description)}")
    lines.append("    next")
    return lines


def _simple_ipv6_vip(vip: Any) -> bool:
    return bool(
        getattr(vip, "address_family", None) == "ipv6"
        and is_generation_safe_object(vip)
        and get_object_extension_value(vip, "vip_type") in {None, "static-nat"}
        and not getattr(vip, "real_servers", [])
        and not getattr(vip, "load_balance_method", None)
    )


def _emit_ipv6_vip(vip: Any) -> list[str]:
    lines = [f"    edit {_quoted(vip.name)}"]
    if getattr(vip, "external_ip", None):
        lines.append(f"        set extip {vip.external_ip}")
    if getattr(vip, "mapped_ips", []):
        lines.append("        set mappedip " + " ".join(vip.mapped_ips))
    if getattr(vip, "external_interface", None):
        lines.append(f"        set extintf {_quoted(vip.external_interface)}")
    if getattr(vip, "port_forward", False):
        lines.append("        set portforward enable")
        if getattr(vip, "protocol", None):
            lines.append(f"        set protocol {vip.protocol}")
        if getattr(vip, "external_port", None):
            lines.append(f"        set extport {vip.external_port}")
        if getattr(vip, "mapped_port", None):
            lines.append(f"        set mappedport {vip.mapped_port}")
    nat46 = get_object_extension_value(vip, "nat46")
    nat64 = get_object_extension_value(vip, "nat64")
    nat66 = get_object_extension_value(vip, "nat66")
    if nat46 is not None:
        lines.append(f"        set nat46 {'enable' if nat46 else 'disable'}")
    if nat64 is not None:
        lines.append(f"        set nat64 {'enable' if nat64 else 'disable'}")
    if nat66 is not None:
        lines.append(f"        set nat66 {'enable' if nat66 else 'disable'}")
    if getattr(vip, "description", None):
        lines.append(f"        set comment {_quoted(vip.description)}")
    lines.append("    next")
    return lines


def _source_vip_filter(vip: Any) -> str | None:
    extra = getattr(vip, "extra_settings", {}) or {}
    value = extra.get("src_vip_filter")
    return value if value in {"enable", "disable"} else None


def _safe_vip_group(group: Any, vip_index: dict[tuple[str, str, str], Any]) -> bool:
    if not is_generation_safe_object(group) or getattr(group, "unresolved_members", []):
        return False
    context = getattr(group, "source_context", None) or "root"
    family = getattr(group, "address_family", "ipv4")
    for member in getattr(group, "members", []):
        vip = vip_index.get((context, family, member))
        if vip is None or not is_generation_safe_object(vip):
            return False
        if family == "ipv6" and not _simple_ipv6_vip(vip):
            return False
        if family == "ipv4" and (
            get_object_extension_value(vip, "vip_type") not in {None, "static-nat"}
            or getattr(vip, "real_servers", [])
            or getattr(vip, "load_balance_method", None)
            or getattr(vip, "source_filters", [])
            or get_object_extension_value(vip, "nat46")
            or get_object_extension_value(vip, "nat64")
        ):
            return False
    return True


def _supplemental_cli(ir: Any) -> str:
    lines: list[str] = []

    ipv4_pools = [
        pool for pool in getattr(ir, "ip_pools", [])
        if getattr(pool, "address_family", "ipv4") == "ipv4"
        and is_generation_safe_object(pool)
        and _advanced_pool(pool)
        and not getattr(pool, "source_attributes", {})
    ]
    if ipv4_pools:
        lines.append("config firewall ippool")
        for pool in ipv4_pools:
            lines.extend(_emit_ipv4_pool(pool))
        lines.append("end")
        lines.append("")

    ipv6_pools = [
        pool for pool in getattr(ir, "ip_pools", [])
        if getattr(pool, "address_family", "ipv4") == "ipv6"
        and is_generation_safe_object(pool)
        and not getattr(pool, "source_attributes", {})
    ]
    if ipv6_pools:
        lines.append("config firewall ippool6")
        for pool in ipv6_pools:
            lines.extend(_emit_ipv6_pool(pool))
        lines.append("end")
        lines.append("")

    ipv6_vips = [vip for vip in getattr(ir, "virtual_ips", []) if _simple_ipv6_vip(vip)]
    if ipv6_vips:
        lines.append("config firewall vip6")
        for vip in ipv6_vips:
            lines.extend(_emit_ipv6_vip(vip))
        lines.append("end")
        lines.append("")

    filtered_vips = [
        vip for vip in getattr(ir, "virtual_ips", [])
        if getattr(vip, "address_family", "ipv4") == "ipv4"
        and is_generation_safe_object(vip)
        and _source_vip_filter(vip) is not None
        and get_object_extension_value(vip, "vip_type") in {None, "static-nat"}
        and not getattr(vip, "real_servers", [])
        and not getattr(vip, "load_balance_method", None)
    ]
    if filtered_vips:
        lines.append("config firewall vip")
        for vip in filtered_vips:
            lines.append(f"    edit {_quoted(vip.name)}")
            lines.append(f"        set src-vip-filter {_source_vip_filter(vip)}")
            lines.append("    next")
        lines.append("end")
        lines.append("")

    vip_index = {
        (
            getattr(vip, "source_context", None) or "root",
            getattr(vip, "address_family", "ipv4"),
            vip.name,
        ): vip
        for vip in getattr(ir, "virtual_ips", [])
    }
    for family, section in (("ipv4", "firewall vipgrp"), ("ipv6", "firewall vipgrp6")):
        groups = [
            group for group in getattr(ir, "virtual_ip_groups", [])
            if getattr(group, "address_family", "ipv4") == family
            and _safe_vip_group(group, vip_index)
        ]
        if not groups:
            continue
        lines.append(f"config {section}")
        for group in groups:
            lines.append(f"    edit {_quoted(group.name)}")
            if getattr(group, "interface", None) and family == "ipv4":
                lines.append(f"        set interface {_quoted(group.interface)}")
            if getattr(group, "members", []):
                values = " ".join(_quoted(member) for member in group.members)
                lines.append(f"        set member {values}")
            if getattr(group, "source_color", None) is not None:
                lines.append(f"        set color {group.source_color}")
            if getattr(group, "description", None):
                lines.append(f"        set comments {_quoted(group.description)}")
            lines.append("    next")
        lines.append("end")
        lines.append("")

    return "\n".join(lines).rstrip()


def install_fortigate_cli_audit_remediation(cli_module: Any) -> None:
    generator_cls = cli_module.FortiGateCLIGenerator
    original = generator_cls.generate
    if getattr(original, "_fortigate_audit_remediation", False):
        return

    def generate(self: Any, ir: Any) -> list[MigrationArtifact]:
        artifacts = original(self, ir)
        if not getattr(ir, "generation_safe", True):
            return artifacts
        supplemental = _supplemental_cli(ir)
        if not supplemental:
            return artifacts
        updated: list[MigrationArtifact] = []
        for artifact in artifacts:
            if artifact.format != "cli":
                updated.append(artifact)
                continue
            content = artifact.content.rstrip() + "\n\n" + supplemental + "\n"
            updated.append(
                MigrationArtifact(
                    filename=artifact.filename,
                    content=content,
                    format=artifact.format,
                )
            )
        return updated

    generate._fortigate_audit_remediation = True
    generator_cls.generate = generate


__all__ = ["install_fortigate_cli_audit_remediation"]
