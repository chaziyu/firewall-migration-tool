"""Short remediation guidance for SRX planning blockers."""


_GUIDANCE = {
    "SOURCE_NAT_PORT_BEHAVIOR_NOT_EXPLICIT": "Keep source NAT manual until the FortiGate source-port choice and Junos behavior are both represented and verified.",
    "SOURCE_NAT_POOL_RETURN_ROUTE_OR_PROXY_ARP_REQUIRED": "Confirm the translated address return route and proxy-ARP ownership before planning pool SNAT.",
    "POLICY_DESTINATION_VIP_DNAT_UNSUPPORTED": "Keep this policy manual until VIP translation and the translated-address policy match can be constrained safely.",
    "CENTRAL_SNAT_EVIDENCE_UNTRANSLATED": "Review the central SNAT rules; they are not represented by per-policy NAT entries.",
    "POLICY_ROUTING_EVIDENCE_UNTRANSLATED": "Review policy-routing behavior before exporting affected policies.",
}


def support_guidance(codes):
    return tuple({
        "code": code,
        "message": _GUIDANCE.get(code, "Keep this item manual until its source and target behavior are verified."),
    } for code in dict.fromkeys(codes))
