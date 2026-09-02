from dataclasses import dataclass

from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATFamily, NATType


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

    def unsupported_reason(self, rule: IRNATRule) -> str | None:
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
        return None


TARGET_NAT_CAPABILITIES = {
    "palo_alto": NATCapabilities(ipv6_nat=True),
    "fortigate": NATCapabilities(
        ipv6_nat=True, nat46=True, nat64=True, nat66=True,
        sctp_address_translation=True, pba=True, cgn=True, pcp=True,
        source_port_policy=True,
    ),
}


def nat_capabilities(target_vendor: str) -> NATCapabilities:
    return TARGET_NAT_CAPABILITIES.get(target_vendor, NATCapabilities())
