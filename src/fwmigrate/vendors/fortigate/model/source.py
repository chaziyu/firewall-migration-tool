from __future__ import annotations

from pydantic import BaseModel, Field

from .address import (
    FGAddress,
    FGAddressGroup,
    FGWildcardFQDN,
)
from .interface import FGInterface
from .ippool import FGIPPool
from .ippool6 import FGIPPool6
from .ips import FGIPSSensor
from .policy import FGPolicy
from .central_snat import FGCentralSNAT
from .route_static import FGStaticRoute
from .sdwan import FGSDWAN
from .security_profile import FGProfileGroup
from .service import FGService, FGServiceGroup, FGServiceCategory
from .schedule import FGScheduleGroup, FGOneTimeSchedule, FGRecurringSchedule
from .vip import FGVIP, FGVIPGroup
from .vip6 import FGVIP6, FGVIPGroup6
from .vpn import FGIPsecPhase1, FGIPsecPhase2, FGIPsecPolicyPhase1, FGIPsecPolicyPhase2
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
    FGSSLVPNClient,
    FGSSLVPNUserBookmark,
    FGSSLVPNUserGroupBookmark,
    FGSSLVPNHostCheckSoftware,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
    FGSSLVPNRealm,
)
from .zone import FGZone
from .external_resource import FGExternalResource
from .firewall_policy_extra import FGPerIPShaper, FGProtocolOptionsProfile, FGSecurityPolicy
from .session_helper import FGSessionHelper
from .selected_sections import (
    FGNACPolicy, FGAddress6Template, FGIPSSettings, FGKMIPServer, FGKerberosKeytab,
    FGRouterSettings, FGSDNProxy, FGOnDemandSniffer, FGAffinityInterrupt,
    FGSerialPort, FGFirewallRegion, FGVendorMAC,
    FGSystemGlobal, FGSystemDNS, FGSystemNTP, FGSystemHA,
    FGSNMPSysinfo, FGSNMPCommunity, FGSNMPUser, FGFortiGuard,
    FGRouterBGP, FGRouterOSPF, FGRouterOSPF6, FGRouterRIP,
    FGPolicyRoute, FGPrefixList, FGRouteMap, FGASPathList, FGCommunityList,
    FGRouterMulticast, FGSystemIPAM, FGFortiExtender,
    FGProxyPolicy, FGAuthPolicy, FGTrafficShaper, FGLDBMonitor,
    FGAntivirusProfile, FGWebFilterProfile, FGURLFilterTable,
    FGWebFilterLocalCategory, FGWebFilterLocalRating, FGWebFilterOverride,
    FGDNSFilterProfile, FGApplicationList, FGFileFilterProfile,
    FGEmailFilterProfile, FGVoIPProfile, FGWAFProfile, FGSSLSSHProfile,
    FGLDAPServer, FGRADIUSServer, FGTACACSServer, FGFSSOServer, FGFSSOPolling,
    FGFortiToken, FGUserSetting, FGPasswordPolicy,
    FGWirelessVAP, FGWirelessWTP, FGWirelessWTPProfile, FGWirelessWIDSProfile,
    FGManagedSwitch, FGSyslogSetting, FGLogMemorySetting, FGLogDiskSetting,
    FGLogSetting, FGLogThreatWeight,
    FGUserGuest, FGSwitchPortPolicy, FGSwitchLLDPProfile, FGSwitchQoSPolicy, FGSwitchVLANPolicy,
)


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
    ip_pools6: list[FGIPPool6] = Field(default_factory=list)

    vips: list[FGVIP] = Field(default_factory=list)
    vip_groups: list[FGVIPGroup] = Field(default_factory=list)
    vips6: list[FGVIP6] = Field(default_factory=list)
    vip_groups6: list[FGVIPGroup6] = Field(default_factory=list)

    policies: list[FGPolicy] = Field(default_factory=list)
    central_snat: list[FGCentralSNAT] = Field(default_factory=list)
    security_policies: list[FGSecurityPolicy] = Field(default_factory=list)
    protocol_options: list[FGProtocolOptionsProfile] = Field(default_factory=list)
    per_ip_shapers: list[FGPerIPShaper] = Field(default_factory=list)
    session_helpers: list[FGSessionHelper] = Field(default_factory=list)
    nac_policies: list[FGNACPolicy] = Field(default_factory=list)
    address6_templates: list[FGAddress6Template] = Field(default_factory=list)
    ips_settings: list[FGIPSSettings] = Field(default_factory=list)
    kmip_servers: list[FGKMIPServer] = Field(default_factory=list)
    kerberos_keytabs: list[FGKerberosKeytab] = Field(default_factory=list)
    router_settings: list[FGRouterSettings] = Field(default_factory=list)
    sdn_proxies: list[FGSDNProxy] = Field(default_factory=list)
    on_demand_sniffers: list[FGOnDemandSniffer] = Field(default_factory=list)
    affinity_interrupts: list[FGAffinityInterrupt] = Field(default_factory=list)
    serial_ports: list[FGSerialPort] = Field(default_factory=list)
    firewall_regions: list[FGFirewallRegion] = Field(default_factory=list)
    vendor_macs: list[FGVendorMAC] = Field(default_factory=list)

    static_routes: list[FGStaticRoute] = Field(default_factory=list)

    ipsec_phase1: list[FGIPsecPhase1] = Field(default_factory=list)
    ipsec_policy_phase1: list[FGIPsecPolicyPhase1] = Field(default_factory=list)
    ipsec_phase2: list[FGIPsecPhase2] = Field(default_factory=list)
    ipsec_policy_phase2: list[FGIPsecPolicyPhase2] = Field(default_factory=list)

    dhcp_servers: list[FGDHCPServer] = Field(default_factory=list)

    sdwans: list[FGSDWAN] = Field(default_factory=list)

    ips_sensors: list[FGIPSSensor] = Field(default_factory=list)
    profile_groups: list[FGProfileGroup] = Field(default_factory=list)

    ssl_vpn_settings: list[FGSSLVPNSettings] = Field(
        default_factory=list
    )
    ssl_vpn_realms: list[FGSSLVPNRealm] = Field(default_factory=list)
    ssl_vpn_clients: list[FGSSLVPNClient] = Field(default_factory=list)
    ssl_vpn_user_bookmarks: list[FGSSLVPNUserBookmark] = Field(default_factory=list)
    ssl_vpn_user_group_bookmarks: list[FGSSLVPNUserGroupBookmark] = Field(default_factory=list)

    ssl_vpn_portals: list[FGSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_host_check_software: list[FGSSLVPNHostCheckSoftware] = Field(default_factory=list)

    local_users: list[FGLocalUser] = Field(default_factory=list)
    user_groups: list[FGUserGroup] = Field(default_factory=list)

    service_categories: list[FGServiceCategory] = Field(default_factory=list)

    administrators: list[FGAdministrator] = Field(default_factory=list)

    admin_profiles: list[FGAdminProfile] = Field(default_factory=list)

    external_resources: list[FGExternalResource] = Field(default_factory=list)

    # System / HA / SNMP / DNS / NTP / FortiGuard
    system_global: tuple[FGSystemGlobal, ...] = ()
    system_dns: tuple[FGSystemDNS, ...] = ()
    system_ntp: tuple[FGSystemNTP, ...] = ()
    ha_config: list[FGSystemHA] = Field(default_factory=list)
    snmp_sysinfo: list[FGSNMPSysinfo] = Field(default_factory=list)
    snmp_communities: list[FGSNMPCommunity] = Field(default_factory=list)
    snmp_users: list[FGSNMPUser] = Field(default_factory=list)
    fortiguard: list[FGFortiGuard] = Field(default_factory=list)

    # Dynamic Routing & Multicast
    router_bgp: list[FGRouterBGP] = Field(default_factory=list)
    router_ospf: list[FGRouterOSPF] = Field(default_factory=list)
    router_ospf6: list[FGRouterOSPF6] = Field(default_factory=list)
    router_rip: list[FGRouterRIP] = Field(default_factory=list)
    policy_routes: list[FGPolicyRoute] = Field(default_factory=list)
    prefix_lists: list[FGPrefixList] = Field(default_factory=list)
    route_maps: list[FGRouteMap] = Field(default_factory=list)
    aspath_lists: list[FGASPathList] = Field(default_factory=list)
    community_lists: list[FGCommunityList] = Field(default_factory=list)
    router_multicast: list[FGRouterMulticast] = Field(default_factory=list)
    system_ipam: list[FGSystemIPAM] = Field(default_factory=list)
    fortiextenders: list[FGFortiExtender] = Field(default_factory=list)

    # Extended Policies & Shapers
    proxy_policies: list[FGProxyPolicy] = Field(default_factory=list)
    auth_policies: list[FGAuthPolicy] = Field(default_factory=list)
    traffic_shapers: list[FGTrafficShaper] = Field(default_factory=list)
    ldb_monitors: list[FGLDBMonitor] = Field(default_factory=list)

    # Security Profiles
    antivirus_profiles: list[FGAntivirusProfile] = Field(default_factory=list)
    webfilter_profiles: list[FGWebFilterProfile] = Field(default_factory=list)
    urlfilter_tables: list[FGURLFilterTable] = Field(default_factory=list)
    webfilter_local_categories: list[FGWebFilterLocalCategory] = Field(default_factory=list)
    webfilter_local_ratings: list[FGWebFilterLocalRating] = Field(default_factory=list)
    webfilter_overrides: list[FGWebFilterOverride] = Field(default_factory=list)
    dnsfilter_profiles: list[FGDNSFilterProfile] = Field(default_factory=list)
    application_lists: list[FGApplicationList] = Field(default_factory=list)
    file_filter_profiles: list[FGFileFilterProfile] = Field(default_factory=list)
    emailfilter_profiles: list[FGEmailFilterProfile] = Field(default_factory=list)
    voip_profiles: list[FGVoIPProfile] = Field(default_factory=list)
    waf_profiles: list[FGWAFProfile] = Field(default_factory=list)
    ssl_ssh_profiles: list[FGSSLSSHProfile] = Field(default_factory=list)

    # User & Auth Extensions
    ldap_servers: list[FGLDAPServer] = Field(default_factory=list)
    radius_servers: list[FGRADIUSServer] = Field(default_factory=list)
    tacacs_servers: list[FGTACACSServer] = Field(default_factory=list)
    fsso_servers: list[FGFSSOServer] = Field(default_factory=list)
    fsso_pollings: list[FGFSSOPolling] = Field(default_factory=list)
    fortitokens: list[FGFortiToken] = Field(default_factory=list)
    user_settings: list[FGUserSetting] = Field(default_factory=list)
    password_policies: list[FGPasswordPolicy] = Field(default_factory=list)

    # WiFi, Switch & Logging
    wireless_vaps: list[FGWirelessVAP] = Field(default_factory=list)
    wireless_wtps: list[FGWirelessWTP] = Field(default_factory=list)
    wtp_profiles: list[FGWirelessWTPProfile] = Field(default_factory=list)
    wids_profiles: list[FGWirelessWIDSProfile] = Field(default_factory=list)
    managed_switches: list[FGManagedSwitch] = Field(default_factory=list)
    syslog_settings: list[FGSyslogSetting] = Field(default_factory=list)
    log_memory_settings: list[FGLogMemorySetting] = Field(default_factory=list)
    log_disk_settings: list[FGLogDiskSetting] = Field(default_factory=list)
    log_settings: list[FGLogSetting] = Field(default_factory=list)
    log_threat_weights: list[FGLogThreatWeight] = Field(default_factory=list)
    guest_users: list[FGUserGuest] = Field(default_factory=list)
    switch_port_policies: list[FGSwitchPortPolicy] = Field(default_factory=list)
    switch_lldp_profiles: list[FGSwitchLLDPProfile] = Field(default_factory=list)
    switch_qos_policies: list[FGSwitchQoSPolicy] = Field(default_factory=list)
    switch_vlan_policies: list[FGSwitchVLANPolicy] = Field(default_factory=list)
