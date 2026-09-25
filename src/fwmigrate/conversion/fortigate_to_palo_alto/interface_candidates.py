"""Conservative, explainable interface candidate comparison."""

from __future__ import annotations

from difflib import SequenceMatcher
from ipaddress import ip_interface
import re


def normalized_name(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def _interfaces(value):
    if not value:
        return ()
    values = value if isinstance(value, (list, tuple, set)) else (value,)
    result = []
    for item in values:
        try:
            parts = str(item).split()
            result.append(ip_interface(f"{parts[0]}/{parts[1]}" if len(parts) == 2 else str(item)))
        except (ValueError, IndexError):
            continue
    return tuple(result)


def _same_subnet(source, target) -> bool:
    return any(
        source_item.network.overlaps(target_item.network)
        or source_item.ip in target_item.network
        or target_item.ip in source_item.network
        for source_item in _interfaces(getattr(source, "ip", None))
        for target_item in _interfaces(getattr(target, "ipv4_addresses", None))
    )


def _parent(target, topology):
    return getattr(target, "parent", None) or getattr(topology, "parent", None)


def candidate_evidence(source, target, topology=None, mapped_parent=None):
    strong, supporting, contradicting = [], [], []
    source_ips = {str(item) for item in _interfaces(getattr(source, "ip", None))}
    target_ips = {str(item) for item in _interfaces(getattr(target, "ipv4_addresses", None))}
    if source_ips & target_ips:
        strong.append(f"exact IP {sorted(source_ips & target_ips)[0]}")
    elif _same_subnet(source, target):
        supporting.append("same IPv4 subnet")

    source_kind = str(getattr(source, "type", "") or "").casefold()
    target_family = str(getattr(target, "interface_family", "") or "").casefold()
    if source_kind == "redundant":
        contradicting.append("redundant source interface is not an aggregate")
    elif source_kind == "aggregate" and target_family != "aggregate-ethernet":
        contradicting.append("interface family mismatch")
    elif source_kind == "tunnel" and target_family != "tunnel":
        contradicting.append("interface family mismatch")
    elif source_kind == "loopback" and target_family != "loopback":
        contradicting.append("interface family mismatch")
    elif source_kind not in {"", "vlan", "aggregate", "tunnel", "loopback"} and target_family != "ethernet":
        contradicting.append("interface family mismatch")

    vlan = getattr(source, "vlanid", None)
    target_tag = getattr(target, "tag", None)
    if vlan is not None:
        if str(vlan) != str(target_tag):
            contradicting.append("VLAN mismatch")
        else:
            supporting.append(f"VLAN {vlan}")
            if mapped_parent and _parent(target, topology) == mapped_parent:
                strong.append(f"confirmed parent {mapped_parent}")
    if mapped_parent and _parent(target, topology) and _parent(target, topology) != mapped_parent:
        contradicting.append("conflicting confirmed parent")

    source_names = {normalized_name(getattr(source, "name", None)), normalized_name(getattr(source, "alias", None)), normalized_name(getattr(source, "description", None))} - {""}
    target_names = {normalized_name(getattr(target, "name", None)), normalized_name(getattr(target, "comment", None))} - {""}
    if normalized_name(getattr(source, "name", None)) and normalized_name(getattr(source, "name", None)) in target_names:
        supporting.append("exact interface name or comment")
    elif source_names & target_names:
        supporting.append("source alias/comment matches target name/comment")
    elif any(SequenceMatcher(None, value, candidate).ratio() >= 0.88 for value in source_names for candidate in target_names):
        supporting.append("normalized interface-name similarity")

    if source_kind == "aggregate" and target_family == "aggregate-ethernet":
        supporting.append("aggregate topology")
    if target_family == "ethernet" and source_kind in {"", "physical"}:
        supporting.append("physical interface family")

    if source_ips & target_ips:
        strong.append("exact IP/prefix")
    elif "same IPv4 subnet" in supporting and vlan is not None and mapped_parent and _parent(target, topology) == mapped_parent:
        strong.append("same subnet + VLAN + confirmed parent")
    return tuple(dict.fromkeys(strong)), tuple(dict.fromkeys(supporting)), tuple(dict.fromkeys(contradicting))


def viable_candidate(source, target, topology=None, mapped_parent=None):
    strong, supporting, contradicting = candidate_evidence(source, target, topology, mapped_parent)
    return not contradicting and bool(strong), strong, supporting, contradicting
