"""Conservative, explainable interface candidate comparison."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from ipaddress import ip_interface
import re


def normalized_name(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


class PANInterfaceCandidateClass(str, Enum):
    STRONG = "STRONG"
    POSSIBLE = "POSSIBLE"
    EXCLUDED = "EXCLUDED"


@dataclass(frozen=True, slots=True)
class PANInterfaceCandidate:
    value: str
    target_scope: str | None
    candidate_class: PANInterfaceCandidateClass
    strong_evidence: tuple[str, ...] = ()
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    assigned_to: tuple[tuple[str, str], ...] = ()
    available: bool = True

    def to_dict(self):
        return {"value": self.value, "target_scope": self.target_scope,
                "class": self.candidate_class.value,
                "strong_evidence": list(self.strong_evidence),
                "supporting_evidence": list(self.supporting_evidence),
                "contradicting_evidence": list(self.contradicting_evidence),
                "available": self.available,
                "assigned_to": [{"source_vdom": vdom, "source_name": name} for vdom, name in self.assigned_to]}


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


def candidate_evidence(source, target, topology=None, mapped_parent=None, evidence=None):
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
    family_matches = ((source_kind == "aggregate" and target_family == "aggregate-ethernet")
        or (source_kind == "tunnel" and target_family == "tunnel")
        or (source_kind == "loopback" and target_family == "loopback")
        or (source_kind == "vlan" and getattr(target, "tag", None) is not None)
        or (source_kind in {"physical", ""} and target_family == "ethernet"))
    if family_matches:
        supporting.append("INTERFACE_FAMILY_MATCH")

    vlan = getattr(source, "vlanid", None)
    target_tag = getattr(target, "tag", None)
    if source_kind in {"physical", "ethernet"} and (target_tag is not None or _parent(target, topology)):
        contradicting.append("physical source cannot map to a target subinterface")
    if vlan is not None:
        if str(vlan) != str(target_tag):
            contradicting.append("VLAN mismatch")
        else:
            supporting.append(f"VLAN {vlan}")
            supporting.append("VLAN_MATCH")
            if mapped_parent and _parent(target, topology) == mapped_parent:
                strong.append(f"confirmed parent {mapped_parent}")
                strong.append("CONFIRMED_PARENT_MATCH")
    if mapped_parent and _parent(target, topology) and _parent(target, topology) != mapped_parent:
        contradicting.append("conflicting confirmed parent")

    source_names = {normalized_name(getattr(source, "name", None)), normalized_name(getattr(source, "alias", None)), normalized_name(getattr(source, "description", None))} - {""}
    target_names = {normalized_name(getattr(target, "name", None)), normalized_name(getattr(target, "comment", None))} - {""}
    if normalized_name(getattr(source, "name", None)) and normalized_name(getattr(source, "name", None)) in target_names:
        supporting.append("exact interface name or comment")
        supporting.append("NAME_MATCH")
    elif source_names & target_names:
        supporting.append("source alias/comment matches target name/comment")
    elif any(SequenceMatcher(None, value, candidate).ratio() >= 0.88 for value in source_names for candidate in target_names):
        supporting.append("normalized interface-name similarity")
        supporting.append("NAME_SIMILARITY")

    if source_kind == "aggregate" and target_family == "aggregate-ethernet":
        supporting.append("aggregate topology")
    if target_family == "ethernet" and source_kind in {"", "physical"}:
        supporting.append("physical interface family")

    if evidence:
        derived = evidence.get("derived_relationships", {})
        source_zone = set(evidence.get("source_explicit", {}).get("zone_membership", ()))
        target_zones = set(getattr(topology, "zones", ()) or ())
        confirmed_zone = evidence.get("confirmed_target_zone")
        if confirmed_zone and target_zones:
            if confirmed_zone in target_zones:
                supporting.append("ZONE_RELATIONSHIP_MATCH")
            else:
                contradicting.append("explicit target zone conflict")
        if source_zone & target_zones:
            supporting.append("ZONE_RELATIONSHIP_MATCH")
        if derived.get("static_route_usage") and getattr(topology, "virtual_routers", ()):
            supporting.append("ROUTE_USAGE_COMPATIBLE")
        target_usage = evidence.get("target_policy_usage", {})
        if ((derived.get("policy_source_reference_count") and target_usage.get("source_reference_count"))
                or (derived.get("policy_destination_reference_count") and target_usage.get("destination_reference_count"))):
            supporting.append("POLICY_ROLE_SIMILAR")
        if derived.get("vpn_names") and getattr(topology, "attached_tunnels", ()):
            source_vpns = set(derived["vpn_names"])
            if source_vpns & set(topology.attached_tunnels):
                strong.append("VPN_TOPOLOGY_MATCH")
        if derived.get("sdwan_membership_count") and getattr(target, "sdwan_enabled", None) == "yes":
            supporting.append("SDWAN_ROLE_MATCH")

    if source_ips & target_ips:
        strong.append("exact IP/prefix")
    elif vlan is not None and str(vlan) == str(getattr(target, "tag", None)) and mapped_parent and _parent(target, topology) == mapped_parent:
        strong.append("same subnet + VLAN + confirmed parent" if "same IPv4 subnet" in supporting
                      else f"VLAN {vlan} + confirmed parent {mapped_parent}")
    return tuple(dict.fromkeys(strong)), tuple(dict.fromkeys(supporting)), tuple(dict.fromkeys(contradicting))


def viable_candidate(source, target, topology=None, mapped_parent=None):
    strong, supporting, contradicting = candidate_evidence(source, target, topology, mapped_parent)
    return not contradicting and bool(strong), strong, supporting, contradicting
