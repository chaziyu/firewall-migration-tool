from __future__ import annotations

from typing import Any, Type

from ..model.address import (
    CPAddressRange, CPDNSDomain, CPDynamicAddress, CPGroup, CPGroupWithExclusion,
    CPHost, CPNetwork, CPUpdatableObject, CPWildcardAddress,
)
from ..model.administration import CPAdministrator, CPPermissionProfile
from ..model.common import CheckPointSourceObject
from ..model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from ..model.identity import CPAccessRole, CPUser, CPUserGroup
from ..model.policy import CPAccessLayer, CPPolicyPackage
from ..model.schedule import CPTime, CPTimeGroup
from ..model.service import CPService, CPServiceGroup
from ..model.source import CPApplication, CPDomain
from ..model.threat import CPThreatLayer, CPThreatProfile
from ..model.vpn import CPVPNCommunity, CPVPNDomain
from ..model.zone import CPSecurityZone
from ..models import CheckPointResponse
from .common import build_source_inventory, build_typed_object, values
from .source_inventory import CheckPointSourceRecord


Dispatch = tuple[Type[CheckPointSourceObject], str, frozenset[str] | None]


_COMMAND_DISPATCH: dict[str, Dispatch] = {
    "show-domains": (CPDomain, "domains", frozenset({"domain"})),
    "show-packages": (CPPolicyPackage, "policy_packages", frozenset({"package"})),
    "show-hosts": (CPHost, "hosts", frozenset({"host"})),
    "show-networks": (CPNetwork, "networks", frozenset({"network"})),
    "show-address-ranges": (CPAddressRange, "address_ranges", frozenset({"address-range", "multicast-address-range"})),
    "show-dns-domains": (CPDNSDomain, "dns_domains", frozenset({"dns", "dns-domain", "domain-name", "domain"})),
    "show-wildcard-objects": (CPWildcardAddress, "wildcard_addresses", frozenset({"wildcard"})),
    "show-dynamic-objects": (CPDynamicAddress, "dynamic_addresses", frozenset({"dynamic", "dynamic-object"})),
    "show-updatable-objects": (CPUpdatableObject, "updatable_objects", frozenset({"updatable", "updatable-object"})),
    "show-groups": (CPGroup, "groups", frozenset({"group"})),
    "show-groups-with-exclusion": (CPGroupWithExclusion, "groups_with_exclusion", frozenset({"group-with-exclusion"})),
    "show-security-zones": (CPSecurityZone, "security_zones", frozenset({"security-zone"})),
    "show-times": (CPTime, "times", frozenset({"time"})),
    "show-time-groups": (CPTimeGroup, "time_groups", frozenset({"time-group"})),
    "show-services-tcp": (CPService, "services", frozenset({"service-tcp"})),
    "show-services-udp": (CPService, "services", frozenset({"service-udp"})),
    "show-services-icmp": (CPService, "services", frozenset({"service-icmp"})),
    "show-services-other": (CPService, "services", frozenset({"service-other"})),
    "show-service-groups": (CPServiceGroup, "service_groups", frozenset({"service-group"})),
    "show-users": (CPUser, "users", frozenset({"user"})),
    "show-user-groups": (CPUserGroup, "user_groups", frozenset({"user-group"})),
    "show-access-roles": (CPAccessRole, "access_roles", frozenset({"access-role"})),
    "show-permission-profiles": (CPPermissionProfile, "permission_profiles", frozenset({"permission-profile"})),
    "show-administrators": (CPAdministrator, "administrators", frozenset({"administrator"})),
    "show-gateways-and-servers": (CPGateway, "gateways", frozenset({"gateway", "checkpointgateway", "simple-gateway"})),
    "show-simple-gateways": (CPGateway, "gateways", frozenset({"gateway", "simple-gateway"})),
    "show-gateways": (CPGateway, "gateways", frozenset({"gateway", "simple-gateway"})),
    "show-simple-clusters": (CPCluster, "clusters", frozenset({"cluster", "simple-cluster"})),
    "show-clusters": (CPCluster, "clusters", frozenset({"cluster", "simple-cluster"})),
    "show-interoperable-devices": (CPInteroperableDevice, "interoperable_devices", frozenset({"interoperable-device"})),
    "show-interoperable-device": (CPInteroperableDevice, "interoperable_devices", frozenset({"interoperable-device"})),
    "show-vpn-communities": (CPVPNCommunity, "vpn_communities", frozenset({"vpn-community"})),
    "show-vpn-domains": (CPVPNDomain, "vpn_domains", frozenset({"vpn-domain"})),
    "show-access-layers": (CPAccessLayer, "access_layers", frozenset({"access-layer"})),
    "show-threat-profiles": (CPThreatProfile, "threat_profiles", frozenset({"threat-profile", "threat-protection-profile"})),
    "show-threat-layers": (CPThreatLayer, "threat_layers", frozenset({"threat-layer", "threat-protection-layer"})),
    "show-threat-protection-layers": (CPThreatLayer, "threat_layers", frozenset({"threat-layer", "threat-protection-layer"})),
}


_TYPE_DISPATCH: dict[str, Dispatch] = {
    "host": (CPHost, "hosts", frozenset({"host"})),
    "network": (CPNetwork, "networks", frozenset({"network"})),
    "address-range": (CPAddressRange, "address_ranges", frozenset({"address-range", "multicast-address-range"})),
    "multicast-address-range": (CPAddressRange, "address_ranges", frozenset({"address-range", "multicast-address-range"})),
    "group": (CPGroup, "groups", frozenset({"group"})),
    "group-with-exclusion": (CPGroupWithExclusion, "groups_with_exclusion", frozenset({"group-with-exclusion"})),
    "security-zone": (CPSecurityZone, "security_zones", frozenset({"security-zone"})),
    "service-group": (CPServiceGroup, "service_groups", frozenset({"service-group"})),
    "service-tcp": (CPService, "services", frozenset({"service-tcp"})),
    "service-udp": (CPService, "services", frozenset({"service-udp"})),
    "service-icmp": (CPService, "services", frozenset({"service-icmp"})),
    "service-other": (CPService, "services", frozenset({"service-other"})),
    "application": (CPApplication, "applications", frozenset({"application", "application-site"})),
    "application-site": (CPApplication, "applications", frozenset({"application", "application-site"})),
    "application-group": (CPApplication, "applications", frozenset({"application-group", "application-site-group"})),
    "application-site-group": (CPApplication, "applications", frozenset({"application-group", "application-site-group"})),
    "application-category": (CPApplication, "applications", frozenset({"application-category", "application-site-category"})),
    "application-site-category": (CPApplication, "applications", frozenset({"application-category", "application-site-category"})),
    "time": (CPTime, "times", frozenset({"time"})),
    "time-group": (CPTimeGroup, "time_groups", frozenset({"time-group"})),
}


def _dispatch(response: CheckPointResponse, value: dict[str, Any]) -> Dispatch | None:
    command = response.command.lower()
    kind = str(value.get("type") or "").strip().lower()
    dispatch = _COMMAND_DISPATCH.get(command)
    if dispatch is None and command == "show-objects":
        dispatch = _TYPE_DISPATCH.get(kind)
    if dispatch is None or (dispatch[2] is not None and kind and kind not in dispatch[2]):
        return None
    return dispatch


def extract_object_records(
    response: CheckPointResponse,
) -> list[tuple[str, CheckPointSourceObject | CheckPointSourceRecord]]:
    records: list[tuple[str, CheckPointSourceObject | CheckPointSourceRecord]] = []
    for order, value in enumerate(values(response), 1):
        dispatch = _dispatch(response, value)
        if dispatch is None:
            records.append(("source_inventory", build_source_inventory(response, value, order)))
            continue
        model, collection, _ = dispatch
        records.append((collection, build_typed_object(response, value, model, order)))
    return records
