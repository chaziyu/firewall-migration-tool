from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod, PANRecommendationReadiness,
    decision_key_if_present, decision_value, recommendation_key, source_facts, target_names,
)


def _selector(prefix, item):
    subnet = getattr(item, f"{prefix}_subnet", None)
    start, end = getattr(item, f"{prefix}_start_ip", None), getattr(item, f"{prefix}_end_ip", None)
    return subnet or (f"{start}-{end}" if start and end else start or end or getattr(item, f"{prefix}_name", None))


def build_vpn_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    phase1s = (*getattr(source, "ipsec_phase1", ()), *getattr(source, "ipsec_policy_phase1", ()))
    phase2s = (*getattr(source, "ipsec_phase2", ()), *getattr(source, "ipsec_policy_phase2", ()))
    phase1_names = {(item.vdom or "root", item.name) for item in phase1s}
    for phase1 in phase1s:
        vdom = phase1.vdom or "root"
        kind = "ipsec_policy_phase1" if phase1.__class__.__name__.startswith("FGIPsecPolicy") else "ipsec_phase1"
        blockers = []
        if kind == "ipsec_policy_phase1":
            blockers.append("Policy-based VPN remains distinct from interface-based VPN")
        decision_key = decision_key_if_present(decisions, vdom, "interface", phase1.interface, "target_interface") if phase1.interface else None
        mapped_interface = decision_value(decisions, decision_key)
        if phase1.interface and not mapped_interface:
            blockers.append("Target interface mapping required")
        blockers.extend(("Target tunnel zone required", "Target virtual router required"))
        evidence = source_facts(phase1, ("interface", "remote_gw", "ike_version", "mode", "authmethod", "dhgrp", "keylife", "nattraversal", "dpd", "localid", "peerid"))
        if phase1.proposal:
            evidence += (f"Phase1 proposals = {', '.join(phase1.proposal)}",)
        if phase1.psk_configured:
            evidence += ("PSK configured = Yes",)
        candidates = target_names(target, "ike_gateways", target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, kind, phase1.name, "PAN_IKE_GATEWAY"), "VPN", vdom, kind, phase1.name,
            "PAN_IKE_GATEWAY", f"IKE gateway {phase1.name}", "Decompose the FortiGate Phase 1 object into a PAN-OS IKE gateway and IKE crypto profile.",
            PANRecommendationMethod.TARGET_EVIDENCE if phase1.name in candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, evidence, candidates, (decision_key,) if decision_key else (), tuple(dict.fromkeys(blockers)), (),
            PANRecommendationReadiness.MANUAL_DESIGN if blockers else PANRecommendationReadiness.SUGGEST))
    for phase2 in phase2s:
        vdom = phase2.vdom or "root"
        kind = "ipsec_policy_phase2" if phase2.__class__.__name__.startswith("FGIPsecPolicy") else "ipsec_phase2"
        blockers = ["Target tunnel interface required", "Target tunnel zone required", "Target virtual router required"]
        if not phase2.phase1name or (vdom, phase2.phase1name) not in phase1_names:
            blockers.append("Referenced Phase 1 gateway is missing")
        if kind == "ipsec_policy_phase2":
            blockers.append("Policy-based VPN remains distinct from interface-based VPN")
        evidence = source_facts(phase2, ("phase1name", "proposal", "pfs", "dhgrp", "keylifeseconds", "protocol", "src_port", "dst_port"))
        for prefix in ("src", "dst"):
            value = _selector(prefix, phase2)
            if value:
                evidence += (f"{prefix} selector = {value}",)
        candidates = target_names(target, "ipsec_tunnels", target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, kind, phase2.name, "PAN_IPSEC_TUNNEL_PROXY_ID"), "VPN", vdom, kind, phase2.name,
            "PAN_IPSEC_TUNNEL_PROXY_ID", f"IPsec selector {phase2.name}", "Decompose the FortiGate Phase 2 object into a PAN-OS IPsec tunnel, crypto profile, and proxy ID.",
            PANRecommendationMethod.TARGET_EVIDENCE if phase2.name in candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, evidence, candidates, (), tuple(dict.fromkeys(blockers)), (),
            PANRecommendationReadiness.MANUAL_DESIGN if blockers else PANRecommendationReadiness.SUGGEST))
    return tuple(result)
