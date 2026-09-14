from dataclasses import dataclass
from typing import Optional

from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATFamily, NATTranslationMode, NATType


@dataclass(frozen=True)
class NATCapabilities:
    ipv6_nat: bool = False
    nat46: bool = False
    nat64: bool = False
    nat66: bool = False
    central_nat: bool = False
    sctp_address_translation: bool = False
    pba: bool = False
    cgn: bool = False
    pcp: bool = False
    source_port_policy: bool = False
    multicast_nat: bool = False
    rtp_nat: bool = False
    persistent_dynamic_ip_and_port: bool = False

    def unsupported_reason(self, rule: IRNATRule) -> str | None:
        if (
            rule.source_translation_mode == NATTranslationMode.PERSISTENT_DYNAMIC_IP_AND_PORT
            and not self.persistent_dynamic_ip_and_port
        ):
            return "persistent dynamic IP-and-port NAT"
        if rule.type == NATType.CENTRAL and not self.central_nat:
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


def plan_fortigate_central_snat(
    rule: IRNATRule, ip_pool_names: set[str] | None = None,
) -> Optional[IRNATRule]:
    """Convert only conservative Check Point source NAT shapes for FortiGate."""
    if rule.type != NATType.SOURCE or rule.identity or rule.exemption:
        return None
    if rule.translated_services or rule.translated_destinations:
        return None
    if rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS:
        if not rule.source_to_interfaces:
            return None
    elif rule.source_translation_mode in {
        NATTranslationMode.STATIC,
        NATTranslationMode.DYNAMIC_IP_AND_PORT,
        NATTranslationMode.POOL,
    }:
        pool_references = list(rule.source_pool_references)
        if not pool_references and ip_pool_names:
            pool_references = [name for name in rule.translated_sources if name in ip_pool_names]
        if not pool_references:
            return None
    else:
        return None
    updates = {
        "type": NATType.CENTRAL,
        "source_origin": "checkpoint-source-nat-to-fortigate-central",
    }
    if rule.source_translation_mode in {
        NATTranslationMode.STATIC,
        NATTranslationMode.DYNAMIC_IP_AND_PORT,
        NATTranslationMode.POOL,
    } and not rule.source_pool_references:
        updates["source_pool_references"] = pool_references
    return rule.model_copy(update=updates)
