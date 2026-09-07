"""Authoritative Check Point R81 Management API collection command registry.

Live collection must use only command names listed here. Historical/synthetic
aliases are parser compatibility only and must never be emitted by the live
collector.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping


@dataclass(frozen=True)
class R81CommandSpec:
    command: str
    expected_response_shape: str = "objects"
    scope_type: str = "DOMAIN"
    pagination_required: bool = True
    required: bool = False


R81_COMMAND_REGISTRY: Dict[str, R81CommandSpec] = {
    # Management/domain and gateway inventory.
    "show-domains": R81CommandSpec("show-domains", scope_type="GLOBAL", required=True),
    "show-gateways-and-servers": R81CommandSpec("show-gateways-and-servers", required=True),
    "show-simple-gateways": R81CommandSpec("show-simple-gateways"),
    "show-simple-clusters": R81CommandSpec("show-simple-clusters"),
    # Network/address objects.
    "show-hosts": R81CommandSpec("show-hosts"),
    "show-networks": R81CommandSpec("show-networks"),
    "show-address-ranges": R81CommandSpec("show-address-ranges"),
    "show-wildcards": R81CommandSpec("show-wildcards"),
    "show-multicast-address-ranges": R81CommandSpec("show-multicast-address-ranges"),
    "show-dynamic-objects": R81CommandSpec("show-dynamic-objects"),
    "show-dns-domains": R81CommandSpec("show-dns-domains"),
    "show-network-feeds": R81CommandSpec("show-network-feeds"),
    "show-checkpoint-hosts": R81CommandSpec("show-checkpoint-hosts"),
    "show-interoperable-devices": R81CommandSpec("show-interoperable-devices"),
    "show-updatable-objects": R81CommandSpec("show-updatable-objects"),
    "show-data-center-objects": R81CommandSpec("show-data-center-objects"),
    "show-groups": R81CommandSpec("show-groups"),
    "show-groups-with-exclusion": R81CommandSpec("show-groups-with-exclusion"),
    "show-security-zones": R81CommandSpec("show-security-zones"),
    # Services.
    "show-services-tcp": R81CommandSpec("show-services-tcp"),
    "show-services-udp": R81CommandSpec("show-services-udp"),
    "show-services-sctp": R81CommandSpec("show-services-sctp"),
    "show-services-icmp": R81CommandSpec("show-services-icmp"),
    "show-services-icmp6": R81CommandSpec("show-services-icmp6"),
    "show-services-other": R81CommandSpec("show-services-other"),
    "show-service-groups": R81CommandSpec("show-service-groups"),
    "show-services-citrix-tcp": R81CommandSpec("show-services-citrix-tcp"),
    "show-services-dce-rpc": R81CommandSpec("show-services-dce-rpc"),
    "show-services-rpc": R81CommandSpec("show-services-rpc"),
    "show-services-gtp": R81CommandSpec("show-services-gtp"),
    "show-services-compound-tcp": R81CommandSpec("show-services-compound-tcp"),
    # Time and policy metadata.
    "show-times": R81CommandSpec("show-times"),
    "show-time-groups": R81CommandSpec("show-time-groups"),
    "show-packages": R81CommandSpec("show-packages", required=True),
    "show-access-layers": R81CommandSpec("show-access-layers"),
    "show-global-assignments": R81CommandSpec("show-global-assignments", scope_type="GLOBAL"),
    # Application/identity inventory currently collected by the R81 path.
    "show-access-roles": R81CommandSpec("show-access-roles"),
    "show-application-sites": R81CommandSpec("show-application-sites"),
    "show-application-site-groups": R81CommandSpec("show-application-site-groups"),
    "show-application-site-categories": R81CommandSpec("show-application-site-categories"),
    "show-identity-sources": R81CommandSpec("show-identity-sources"),
    # VPN / AAA / certificates.
    "show-vpn-communities-meshed": R81CommandSpec("show-vpn-communities-meshed"),
    "show-vpn-communities-star": R81CommandSpec("show-vpn-communities-star"),
    "show-vpn-communities-remote-access": R81CommandSpec("show-vpn-communities-remote-access"),
    "show-ldap-accounts": R81CommandSpec("show-ldap-accounts"),
    "show-radius-servers": R81CommandSpec("show-radius-servers"),
    "show-tacacs-servers": R81CommandSpec("show-tacacs-servers"),
    "show-saml-identity-providers": R81CommandSpec("show-saml-identity-providers"),
    "show-authentication-methods": R81CommandSpec("show-authentication-methods"),
    "show-server-certificates": R81CommandSpec("show-server-certificates"),
    # Threat Prevention / rulebases.
    "show-threat-profiles": R81CommandSpec("show-threat-profiles"),
    "show-access-rulebase": R81CommandSpec(
        "show-access-rulebase", expected_response_shape="rulebase", scope_type="ACCESS_LAYER", required=True
    ),
    "show-nat-rulebase": R81CommandSpec(
        "show-nat-rulebase", expected_response_shape="rulebase", scope_type="PACKAGE", required=True
    ),
    "show-threat-rulebase": R81CommandSpec(
        "show-threat-rulebase", expected_response_shape="rulebase", scope_type="PACKAGE"
    ),
    # Official R81 HTTPS Inspection rulebase command.
    "show-https-rulebase": R81CommandSpec(
        "show-https-rulebase", expected_response_shape="rulebase", scope_type="PACKAGE"
    ),
}


# Compatibility aliases accepted only while reading old bundles/fixtures.
# They are intentionally absent from R81_COMMAND_REGISTRY.
LEGACY_COMMAND_ALIASES: Mapping[str, str] = {
    "show-https-inspection-rulebase": "show-https-rulebase",
    "show-https-inspection-policy": "show-https-rulebase",
    "show-threat-prevention-profiles": "show-threat-profiles",
}


def canonical_r81_command(command: str) -> str:
    """Return the canonical live R81 command for a normalized command name."""
    return LEGACY_COMMAND_ALIASES.get(command, command)


def is_live_r81_command(command: str) -> bool:
    """True only for commands the live R81 collector is allowed to emit."""
    return command in R81_COMMAND_REGISTRY
