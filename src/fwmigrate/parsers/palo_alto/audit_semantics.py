"""Targeted PAN-OS semantic corrections from the Palo Alto extraction audit.

This module deliberately patches only the final registered parser path.  The
base extractor modules remain reusable, while normal ``palo_alto`` imports get
correct PAN-OS hierarchy and literal/reference classification behavior.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from . import nat as nat_module
from . import pbf as pbf_module
from . import routing as routing_module
from .xml_utils import collect_unknown_children, member_texts, text_or_none


_BASE_NAT_RESOLVE = nat_module._resolve
_INSTALLED = False
_FQDN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_ip_host_or_prefix(value: str) -> bool:
    raw = (value or "").strip()
    if not raw:
        return False
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(raw, strict=False)
        return True
    except ValueError:
        return False


def _is_fqdn(value: str) -> bool:
    raw = (value or "").strip().rstrip(".")
    # Require a dotted name so unresolved single-token object names cannot be
    # silently reclassified as literal FQDN selectors.
    if not raw or "." not in raw or len(raw) > 253:
        return False
    labels = raw.split(".")
    return all(label and len(label) <= 63 and _FQDN_LABEL.fullmatch(label) for label in labels)


def _is_direct_pbf_address(value: str) -> bool:
    return _is_ip_host_or_prefix(value) or _is_fqdn(value)


def _is_direct_nat_match_address(value: str) -> bool:
    # Keep NAT match classification intentionally narrower than translated
    # address parsing.  Direct host/prefix values are valid match selectors;
    # object/group references still go through the scoped resolver.
    return _is_ip_host_or_prefix(value)


class PANAuditedRouteExtractor(routing_module.PANRouteExtractor):
    """Use the documented static-route path-monitor hierarchy and bounds."""

    @staticmethod
    def _path_monitor_int(
        node: ET.Element,
        paths: tuple[str, ...],
        reasons: list[str],
    ) -> int | None:
        is_count = any("count" in path for path in paths)
        minimum, maximum = (3, 10) if is_count else (1, 60)
        for path in paths:
            raw = text_or_none(node, path)
            if raw is None:
                continue
            try:
                value = int(raw)
            except ValueError:
                reasons.append(f"{path} must be an integer, found {raw!r}")
                return None
            if not minimum <= value <= maximum:
                reasons.append(
                    f"{path} must be between {minimum} and {maximum}, found {raw!r}"
                )
                return None
            return value
        return None

    @staticmethod
    def _path_monitor_entries(path_monitor: ET.Element) -> list[ET.Element]:
        entries: list[ET.Element] = []
        seen: set[int] = set()
        # monitor-destinations is the PAN-OS hierarchy.  The remaining paths
        # are retained only for backward-compatible parsing of older fixtures
        # and exports already accepted by this project.
        for path in (
            "./monitor-destinations/entry",
            "./destination/entry",
            "./monitor-dest/entry",
            "./monitor-destination/entry",
            "./destinations/entry",
            "./entry",
        ):
            for entry in path_monitor.findall(path):
                if id(entry) not in seen:
                    entries.append(entry)
                    seen.add(id(entry))
        return entries

    @staticmethod
    def _path_monitor_destination_nodes(path_monitor: ET.Element) -> list[ET.Element]:
        entries = PANAuditedRouteExtractor._path_monitor_entries(path_monitor)
        if entries:
            return entries
        return [
            node
            for path in (
                "./monitor-dest",
                "./destination",
                "./monitor-destination",
                "./monitor-dest/member",
                "./destination/member",
            )
            for node in path_monitor.findall(path)
            if text_or_none(node, ".")
        ]


class PANAuditedPBFRuleExtractor(pbf_module.PANPBFRuleExtractor):
    """Resolve PBF scalar addresses only after scoped object resolution fails."""

    @staticmethod
    def _resolve_values(resolver, values, namespace, scope, builtins=()):
        if resolver is None:
            return list(values), []
        resolved_values: list[str] = []
        unresolved: list[str] = []
        builtin_values = {value.lower() for value in builtins}
        for value in values:
            if value.lower() in builtin_values:
                resolved_values.append(value)
                continue
            obj = resolver.resolve(value, namespace, scope)
            if obj is not None:
                resolved_values.append(obj.canonical_name or value)
                continue
            if namespace == "address-reference" and _is_direct_pbf_address(value):
                resolved_values.append(value)
                continue
            unresolved.append(value)
            resolved_values.append(value)
        return resolved_values, unresolved


def _extract_symmetric_return(
    node: ET.Element | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Parse PAN-OS enforce-symmetric-return next-hop-address-list entries."""
    if node is None:
        return None, None
    enabled, issue = pbf_module._strict_yes_no(node, "./enabled")
    addresses: list[str] = []

    address_list = node.find("./nexthop-address-list")
    if address_list is not None:
        for entry in address_list.findall("./entry"):
            value = (entry.get("name") or "").strip()
            if value:
                addresses.append(value)
        # Keep tolerant support for member-form exports without treating that
        # compatibility form as the canonical PAN-OS hierarchy.
        addresses.extend(member_texts(address_list, "./member"))

    # Backward-compatible aliases previously accepted by the extractor.
    if address_list is None:
        for child_name in ("nexthop-address", "next-hop-address"):
            child = node.find(f"./{child_name}")
            if child is None:
                continue
            values = member_texts(child, "./member")
            if not values:
                value = (child.text or "").strip()
                values = [value] if value else []
            addresses.extend(values)

    known_fields = [
        "enabled",
        "nexthop-address-list",
        "nexthop-address",
        "next-hop-address",
    ]
    return {
        "enabled": enabled,
        "next_hop_addresses": addresses,
        "unknown_fields": collect_unknown_children(node, known_fields),
    }, issue


def _resolve_nat_values(
    resolver,
    values: list[str],
    namespace: str,
    scope,
    builtins: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Resolve NAT match addresses without misclassifying direct literals."""
    if namespace != "address-reference":
        return _BASE_NAT_RESOLVE(resolver, values, namespace, scope, builtins)

    output: list[str] = []
    unresolved: list[str] = []
    builtin_values = {value.lower() for value in (builtins or set())}
    for value in values:
        if value.lower() in builtin_values:
            output.append(value)
            continue
        obj = resolver.resolve(value, namespace, scope)
        if obj is not None:
            output.append(obj.canonical_name or value)
            continue
        if _is_direct_nat_match_address(value):
            output.append(value)
            continue
        unresolved.append(value)
        output.append(value)
    return output, unresolved


def install_audit_semantic_fixes() -> None:
    """Install the corrections into the final registered PAN-OS parser path."""
    global _INSTALLED
    if _INSTALLED:
        return

    # Import lazily to avoid package-initialization cycles.  These modules have
    # already been loaded by the registered parser chain when this function is
    # called, so replacing their imported extractor globals is deterministic.
    from . import parser as parser_module
    from . import policy_families as policy_families_module

    routing_module.PANRouteExtractor = PANAuditedRouteExtractor
    parser_module.PANRouteExtractor = PANAuditedRouteExtractor

    pbf_module.PBF_SYMMETRIC_RETURN_ADDRESS_FIELDS = (
        "nexthop-address-list",
        "nexthop-address",
        "next-hop-address",
    )
    pbf_module.PBF_SYMMETRIC_RETURN_FIELDS = [
        "enabled",
        *pbf_module.PBF_SYMMETRIC_RETURN_ADDRESS_FIELDS,
    ]
    pbf_module._extract_symmetric_return = _extract_symmetric_return
    pbf_module.PANPBFRuleExtractor = PANAuditedPBFRuleExtractor
    policy_families_module.PANPBFRuleExtractor = PANAuditedPBFRuleExtractor

    # PANNatRuleExtractor methods resolve this module global at runtime, so the
    # registered parser immediately receives literal-first match handling.
    nat_module._resolve = _resolve_nat_values

    _INSTALLED = True
