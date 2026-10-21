"""Short remediation guidance for SRX planning blockers."""


_GUIDANCE = {
    "DYNAMIC_FABRIC_ADDRESS_UNSUPPORTED": "FABRIC_DEVICE is populated dynamically by the FortiGate Security Fabric. Its configured subnet is not the policy match set; rebuild its runtime membership before translating dependent rules.",
    "INTERFACE_CONTROL_PLANE_REQUIRES_SEPARATE_DESIGN": "Interface addressing can be reviewed separately. Rebuild administrative access, trusted-host restrictions, authentication and discovery settings before device use; no host-inbound services are enabled by this export.",
    "SERVICE_USES_BUILTIN_ANY": "The unrestricted source IP service is mapped to Junos application any in policy matches. It does not require a custom target application.",
    "FQDN_RUNTIME_SEMANTICS_UNVERIFIED": "FQDN conversion requires verified DNS resolution, address-family and cache behavior. Preserve the hostname and review target DNS behavior before exporting affected rules.",
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
