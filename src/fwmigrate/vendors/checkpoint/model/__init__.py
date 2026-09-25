"""Canonical Check Point source models."""

from .address import (
    CPAddress, CPAddressGroup, CPAddressRange, CPDNSDomain, CPDynamicAddress,
    CPGroup, CPGroupWithExclusion, CPHost, CPNetwork, CPUpdatableObject, CPWildcardAddress,
)
from .administration import CPAdministrator, CPPermissionProfile
from .common import CheckPointObjectReference, CheckPointSourceObject, ManagementDomain
from .gateway import CPCluster, CPGateway, CPGatewayInterface, CPInteroperableDevice
from .gaia import (
    CPGaiaDHCPPool, CPGaiaDHCPServer, CPGaiaDHCPSubnet, CPGaiaInterface, CPGaiaRouteNextHop,
    CPGaiaRBAUserAssignment, CPGaiaRBARole, CPGaiaStaticRoute, CPGaiaUser, CPVTI,
)
from .identity import CPAccessRole, CPUser, CPUserGroup
from .policy import (
    CPAccessLayer, CPAccessRule, CPAccessSection, CPAutoNATRule, CPManualNATRule,
    CPNATRule, CPNATSection, CPPolicyPackage,
)
from .schedule import CPTime, CPTimeGroup
from .service import CPService, CPServiceGroup
from .threat import CPHTTPSInspectionRule, CPThreatLayer, CPThreatProfile, CPThreatRule, CPThreatRuleException, CPThreatSection
from .vpn import CPVPNCommunity, CPVPNDomain
from .zone import CPSecurityZone
from ..models import CheckPointCollectionDiagnostic
from .source import CheckPointConfig

__all__ = [
    "CPAccessLayer", "CPAccessRule", "CPAddress", "CPAddressGroup", "CPAutoNATRule",
    "CPManualNATRule", "CPAccessLayer", "CPAccessRule", "CPAccessSection", "CPAccessRole",
    "CPAdministrator", "CPAddressRange", "CPCluster", "CPHTTPSInspectionRule",
    "CPDNSDomain", "CPDynamicAddress", "CPGaiaDHCPPool", "CPGaiaDHCPServer",
    "CPGaiaDHCPSubnet", "CPGaiaInterface", "CPGaiaRBAUserAssignment", "CPGaiaRBARole",
    "CPGaiaStaticRoute", "CPGaiaRouteNextHop", "CPGaiaUser", "CPGateway", "CPGatewayInterface", "CPGroup",
    "CPGroupWithExclusion", "CPHost", "CPNetwork", "CPService", "CPServiceGroup", "CPSecurityZone",
    "CPInteroperableDevice", "CPNATRule", "CPNATSection", "CPPermissionProfile", "CPPolicyPackage",
    "CPThreatLayer", "CPThreatProfile", "CPThreatRule", "CPThreatRuleException", "CPThreatSection",
    "CPTime", "CPTimeGroup", "CPUpdatableObject", "CPVTI",
    "CPUser", "CPUserGroup", "CPVPNCommunity", "CPVPNDomain", "CPWildcardAddress",
    "CheckPointCollectionDiagnostic", "CheckPointConfig",
    "CheckPointObjectReference", "CheckPointSourceObject",
    "ManagementDomain",
]
