from dataclasses import dataclass
from typing import Optional

from fwmigrate.ir.nat import IRNATRule
from fwmigrate.ir.enums import NATFamily, NATTranslationMode, NATType


@dataclass(frozen=True)
class NATCapabilities:
    ipv6_nat: bool = False
    nat46: bool = False
    nat64: bool = False
    nat66: bool = False
    central_nat: bool = False
    static_nat: bool = False
    sctp_address_translation: bool = False
    pba: bool = False
    cgn: bool = False
    pcp: bool = False
    source_port_policy: bool = False
    multicast_nat: bool = False
    rtp_nat: bool = False
    persistent_dynamic_ip_and_port: bool = False

    def unsupported_reason(self, rule: IRNATRule) -> str | None:
        if rule.type == NATType.STATIC and not self.static_nat:
            return "static NAT"
        if (
            rule.source_translation_mode == NATTranslationMode.PERSISTENT_DYNAMIC_IP_AND_PORT
            and not self.persistent_dynamic_ip_and_port
        ):
            return "persistent dynamic IP-and-port NAT"
        if rule.is_central_rulebase and not self.central_nat:
            return "central NAT"
        if rule.type == NATType.ADDRESS_TRANSLATION and not self.sctp_address_translation:
            return "SCTP address translation"
        if rule.nat_family == NATFamily.NAT46 and not self.nat46:
            return "NAT46"
        if rule.nat_family == NATFamily.NAT64 and not self.nat64:
            return "NAT64"
        if rule.nat_family == NATFamily.NAT66 and not self.nat66:
            return "NAT66"
        if rule.original_address_family == "ipv6" and not self.ipv6_nat:
            return "IPv6 NAT"
        if rule.runtime_behavior and (
            rule.runtime_behavior.pcp_inbound or rule.runtime_behavior.pcp_outbound
        ) and not self.pcp:
            return "PCP NAT"
        if rule.runtime_behavior and rule.runtime_behavior.fixed_port and not self.source_port_policy:
            return "fixed source-port policy"
        if rule.traffic_type == "multicast" and not self.multicast_nat:
            return "multicast NAT"
        if rule.runtime_behavior and rule.runtime_behavior.rtp_nat and not self.rtp_nat:
            return "RTP NAT"
        return None


TARGET_NAT_CAPABILITIES = {
    "palo_alto": NATCapabilities(ipv6_nat=True),
    "fortigate": NATCapabilities(
        ipv6_nat=True, nat46=True, nat64=True, nat66=True,
        central_nat=True, multicast_nat=True, rtp_nat=True,
        sctp_address_translation=True, pba=True, cgn=True, pcp=True,
        source_port_policy=True,
    ),
}


def nat_capabilities(target_vendor: str) -> NATCapabilities:
    return TARGET_NAT_CAPABILITIES.get(target_vendor, NATCapabilities())


def checkpoint_fortigate_central_snat_reason(
    rule: IRNATRule, ip_pool_names: set[str] | None = None,
) -> str | None:
    """Return a review reason when Check Point source NAT is not portable."""
    if rule.type != NATType.SOURCE or rule.identity or rule.exemption:
        return None
    attributes = rule.source_attributes or {}
    if attributes.get("checkpoint-nat-origin") == "automatic" or rule.source_origin == "automatic":
        if attributes.get("checkpoint-ordering-barrier") or attributes.get("checkpoint-preceding-identity-rules"):
            return "checkpoint-automatic-nat-ordering-not-portable"
        return "checkpoint-automatic-nat-equivalence-not-proven"
    if attributes.get("checkpoint-ordering-barrier"):
        return "checkpoint-nat-ordering-not-portable"
    if rule.translated_services or rule.translated_destinations:
        return "checkpoint-translated-fields-not-portable"
    resolution = attributes.get("checkpoint-source-nat-method-resolution")
    if isinstance(resolution, dict) and (
        resolution.get("resolved") is not True or resolution.get("reasons")
    ):
        return "checkpoint-source-nat-method-evidence-incomplete"
    if rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS:
        return None if rule.source_to_interfaces else "checkpoint-hide-gateway-unresolved"
    if rule.source_translation_mode in {
        NATTranslationMode.STATIC,
        NATTranslationMode.DYNAMIC_IP_AND_PORT,
        NATTranslationMode.POOL,
    }:
        if rule.source_pool_references:
            return None
        if ip_pool_names and any(name in ip_pool_names for name in rule.translated_sources):
            return "checkpoint-management-ip-pool-not-generic-snat"
        return "checkpoint-source-pool-unresolved"
    return "checkpoint-source-nat-method-unresolved"


def plan_fortigate_central_snat(
    rule: IRNATRule, ip_pool_names: set[str] | None = None,
) -> Optional[IRNATRule]:
    """Convert only conservative Check Point source NAT shapes for FortiGate."""
    if checkpoint_fortigate_central_snat_reason(rule, ip_pool_names):
        return None
    if rule.type != NATType.SOURCE or rule.identity or rule.exemption:
        return None
    updates = {
        "type": NATType.SOURCE,
        "source_origin": "checkpoint-source-nat-to-fortigate-central",
    }
    return rule.model_copy(update=updates)
