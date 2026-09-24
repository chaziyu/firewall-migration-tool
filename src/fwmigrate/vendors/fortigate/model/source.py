from __future__ import annotations

from pydantic import BaseModel, Field

from .address import (
    FGAddress,
    FGAddressGroup,
    FGWildcardFQDN,
)
from .interface import FGInterface
from .ippool import FGIPPool
from .ips import FGIPSSensor
from .policy import FGPolicy
from .route_static import FGStaticRoute
from .sdwan import FGSDWAN
from .security_profile import FGProfileGroup
from .service import FGService, FGServiceGroup, FGServiceCategory
from .schedule import FGScheduleGroup, FGOneTimeSchedule, FGRecurringSchedule
from .vip import FGVIP, FGVIPGroup
from .vpn import FGIPsecPhase1, FGIPsecPhase2
from .admin import (
    FGAdministrator,
    FGAdminProfile,
)
from .dhcp import FGDHCPServer
from .user import (
    FGLocalUser,
    FGUserGroup,
)
from .vpn_ssl import (
    FGSSLVPNHostCheckSoftware,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
)
from .zone import FGZone
from .external_resource import FGExternalResource


class FGConfig(BaseModel):
    """Aggregate of extracted FortiGate source objects."""

    interfaces: list[FGInterface] = Field(default_factory=list)

    zones: list[FGZone] = Field(default_factory=list)

    addresses: list[FGAddress] = Field(default_factory=list)
    address_groups: list[FGAddressGroup] = Field(default_factory=list)
    wildcard_fqdns: list[FGWildcardFQDN] = Field(default_factory=list)

    services: list[FGService] = Field(default_factory=list)
    service_groups: list[FGServiceGroup] = Field(default_factory=list)

    schedule_groups: list[FGScheduleGroup] = Field(default_factory=list)
    one_time_schedules: list[FGOneTimeSchedule] = Field(default_factory=list)
    recurring_schedules: list[FGRecurringSchedule] = Field(default_factory=list)

    ip_pools: list[FGIPPool] = Field(default_factory=list)

    vips: list[FGVIP] = Field(default_factory=list)
    vip_groups: list[FGVIPGroup] = Field(default_factory=list)

    policies: list[FGPolicy] = Field(default_factory=list)

    static_routes: list[FGStaticRoute] = Field(default_factory=list)

    ipsec_phase1: list[FGIPsecPhase1] = Field(default_factory=list)
    ipsec_phase2: list[FGIPsecPhase2] = Field(default_factory=list)

    dhcp_servers: list[FGDHCPServer] = Field(default_factory=list)

    sdwans: list[FGSDWAN] = Field(default_factory=list)

    ips_sensors: list[FGIPSSensor] = Field(default_factory=list)
    profile_groups: list[FGProfileGroup] = Field(default_factory=list)

    ssl_vpn_settings: list[FGSSLVPNSettings] = Field(
        default_factory=list
    )

    ssl_vpn_portals: list[FGSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_host_check_software: list[FGSSLVPNHostCheckSoftware] = Field(default_factory=list)

    local_users: list[FGLocalUser] = Field(default_factory=list)
    user_groups: list[FGUserGroup] = Field(default_factory=list)

    service_categories: list[FGServiceCategory] = Field(default_factory=list)

    administrators: list[FGAdministrator] = Field(default_factory=list)

    admin_profiles: list[FGAdminProfile] = Field(default_factory=list)

    external_resources: list[FGExternalResource] = Field(default_factory=list)
