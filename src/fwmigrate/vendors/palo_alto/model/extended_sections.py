from __future__ import annotations

from typing import Any

from pydantic import Field

from .common import PANNamedSourceModel


# ----------------------------------------------------------------------
# System / Device Setup / HA
# ----------------------------------------------------------------------


class PANSystemSettings(PANNamedSourceModel):
    hostname: str | None = None
    ip_address: str | None = None
    netmask: str | None = None
    default_gateway: str | None = None
    ipv6_address: str | None = None
    ipv6_default_gateway: str | None = None
    timezone: str | None = None
    domain: str | None = None
    update_server: str | None = None
    advanced_routing: str | None = None
    login_banner: str | None = None
    type: str | None = None
    dns_setting: dict[str, Any] | None = None
    ntp_servers: dict[str, Any] | None = None
    service: dict[str, Any] | None = None
    route: dict[str, Any] | None = None
    panorama: dict[str, Any] | None = None
    snmp_setting: dict[str, Any] | None = None
    permitted_ip: list[str] | None = None


class PANHAConfig(PANNamedSourceModel):
    enabled: str | None = None
    mode: dict[str, Any] | None = None
    group: dict[str, Any] | None = None
    interface: dict[str, Any] | None = None
    election_option: dict[str, Any] | None = None
    state_synchronization: dict[str, Any] | None = None
    monitoring: dict[str, Any] | None = None


class PANDeviceSetupSetting(PANNamedSourceModel):
    config: dict[str, Any] | None = None
    management: dict[str, Any] | None = None
    wildfire: dict[str, Any] | None = None
    tcp: dict[str, Any] | None = None
    session: dict[str, Any] | None = None
    logging: dict[str, Any] | None = None
    ctd: dict[str, Any] | None = None
    application: dict[str, Any] | None = None
    alarm: dict[str, Any] | None = None
    user_id_collector: dict[str, Any] | None = None


# ----------------------------------------------------------------------
# Extended Policy Families
# ----------------------------------------------------------------------


class PANQoSRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    source_user: list[str] | None = None
    application: list[str] | None = None
    service: list[str] | None = None
    category: list[str] | None = None
    schedule: str | None = None
    qos_class: str | None = None
    dscp_marking: dict[str, Any] | None = None
    negate_source: str | None = None
    negate_destination: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANPBFRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    from_interfaces: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    source_user: list[str] | None = None
    application: list[str] | None = None
    service: list[str] | None = None
    schedule: str | None = None
    action: str | None = None
    egress_interface: str | None = None
    nexthop: str | None = None
    enforce_symmetric_return: dict[str, Any] | None = None
    active_active_device_binding: str | None = None
    negate_source: str | None = None
    negate_destination: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANDecryptionRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    source_user: list[str] | None = None
    service: list[str] | None = None
    category: list[str] | None = None
    source_hip: list[str] | None = None
    destination_hip: list[str] | None = None
    action: str | None = None
    type: dict[str, Any] | None = None
    profile: str | None = None
    log_setting: str | None = None
    negate_source: str | None = None
    negate_destination: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANTunnelInspectRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    tunnel_protocol: str | None = None
    action: str | None = None
    profile: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANAppOverrideRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    protocol: str | None = None
    port: str | None = None
    application: str | None = None
    negate_source: str | None = None
    negate_destination: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANAuthenticationRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    source_user: list[str] | None = None
    service: list[str] | None = None
    category: list[str] | None = None
    source_hip: list[str] | None = None
    destination_hip: list[str] | None = None
    authentication_enforcement: str | None = None
    action: str | None = None
    timeout: str | None = None
    log_setting: str | None = None
    negate_source: str | None = None
    negate_destination: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANDoSRule(PANNamedSourceModel):
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    source_user: list[str] | None = None
    service: list[str] | None = None
    action: dict[str, Any] | None = None
    protection: dict[str, Any] | None = None
    schedule: str | None = None
    log_setting: str | None = None
    disabled: str | None = None
    description: str | None = None
    tags: list[str] | None = None


# ----------------------------------------------------------------------
# Extended Objects & Security Profiles
# ----------------------------------------------------------------------


class PANApplicationGroup(PANNamedSourceModel):
    members: list[str] | None = None
    disable_override: str | None = None


class PANRegion(PANNamedSourceModel):
    addresses: list[str] | None = None
    geo_location: dict[str, Any] | None = None


class PANDynamicUserGroup(PANNamedSourceModel):
    filter: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PANHIPObject(PANNamedSourceModel):
    description: str | None = None
    host_info: dict[str, Any] | None = None
    network_info: dict[str, Any] | None = None
    patch_management: dict[str, Any] | None = None
    disk_backup: dict[str, Any] | None = None
    disk_encryption: dict[str, Any] | None = None
    mobile_device: dict[str, Any] | None = None
    certificate: dict[str, Any] | None = None


class PANHIPProfile(PANNamedSourceModel):
    match: str | None = None
    description: str | None = None


class PANExternalList(PANNamedSourceModel):
    type: dict[str, Any] | None = None
    description: str | None = None
    url: str | None = None
    certificate_profile: str | None = None
    username: str | None = None
    password_configured: bool | None = None
    recurring: dict[str, Any] | None = None


class PANCustomURLCategory(PANNamedSourceModel):
    list_entries: list[str] | None = None
    type: str | None = None
    description: str | None = None


class PANDataPattern(PANNamedSourceModel):
    description: str | None = None
    pattern_type: dict[str, Any] | None = None


class PANCustomThreat(PANNamedSourceModel):
    threat_type: str | None = None
    threatname: str | None = None
    severity: str | None = None
    category: str | None = None
    default_action: dict[str, Any] | None = None
    comment: str | None = None


class PANAntivirusProfile(PANNamedSourceModel):
    description: str | None = None
    packet_capture: str | None = None
    decoders: list[dict[str, Any]] | None = None
    applications: list[dict[str, Any]] | None = None
    threat_exceptions: list[dict[str, Any]] | None = None


class PANAntiSpywareProfile(PANNamedSourceModel):
    description: str | None = None
    cloud_inline_analysis: str | None = None
    botnet_domains: dict[str, Any] | None = None
    rules: list[dict[str, Any]] | None = None
    threat_exceptions: list[dict[str, Any]] | None = None


class PANURLFilteringProfile(PANNamedSourceModel):
    description: str | None = None
    allow: list[str] | None = None
    alert: list[str] | None = None
    block: list[str] | None = None
    continue_categories: list[str] | None = None
    override_categories: list[str] | None = None
    credential_enforcement: dict[str, Any] | None = None
    log_http_hdr_xff: str | None = None
    log_http_hdr_user_agent: str | None = None
    log_http_hdr_referer: str | None = None
    safe_search_enforcement: str | None = None


class PANFileBlockingProfile(PANNamedSourceModel):
    description: str | None = None
    rules: list[dict[str, Any]] | None = None


class PANWildFireProfile(PANNamedSourceModel):
    description: str | None = None
    rules: list[dict[str, Any]] | None = None


class PANDataFilteringProfile(PANNamedSourceModel):
    description: str | None = None
    data_capture: str | None = None
    rules: list[dict[str, Any]] | None = None


class PANDoSProtectionProfile(PANNamedSourceModel):
    description: str | None = None
    type: str | None = None
    flood: dict[str, Any] | None = None
    resource: dict[str, Any] | None = None


class PANDecryptionProfile(PANNamedSourceModel):
    ssl_forward_proxy: dict[str, Any] | None = None
    ssl_inbound_proxy: dict[str, Any] | None = None
    ssl_no_proxy: dict[str, Any] | None = None
    ssl_protocol_settings: dict[str, Any] | None = None
    ssh_proxy: dict[str, Any] | None = None


class PANLogForwardingProfile(PANNamedSourceModel):
    description: str | None = None
    enhanced_application_logging: str | None = None
    match_list: list[dict[str, Any]] | None = None


class PANAuthenticationProfile(PANNamedSourceModel):
    method: dict[str, Any] | None = None
    allow_list: list[str] | None = None
    username_modifier: str | None = None
    user_domain: str | None = None
    single_sign_on: dict[str, Any] | None = None
    lockout: dict[str, Any] | None = None
    multi_factor_auth: dict[str, Any] | None = None


class PANAuthenticationSequence(PANNamedSourceModel):
    authentication_profiles: list[str] | None = None
    use_domain_find_profile: str | None = None


# ----------------------------------------------------------------------
# Network Extensions
# ----------------------------------------------------------------------


class PANVLAN(PANNamedSourceModel):
    virtual_interface: str | None = None
    interfaces: list[str] | None = None
    mac: list[dict[str, Any]] | None = None


class PANVirtualWire(PANNamedSourceModel):
    interface1: str | None = None
    interface2: str | None = None
    tag_allowed: str | None = None
    link_state_pass_through: dict[str, Any] | None = None
    multicast_firewalling: dict[str, Any] | None = None


class PANGRETunnel(PANNamedSourceModel):
    tunnel_interface: str | None = None
    local_address: dict[str, Any] | None = None
    peer_address: dict[str, Any] | None = None
    ttl: str | None = None
    copy_tos: str | None = None
    keep_alive: dict[str, Any] | None = None
    disabled: str | None = None


class PANDNSProxy(PANNamedSourceModel):
    interfaces: list[str] | None = None
    default_primary: str | None = None
    default_secondary: str | None = None
    cache: dict[str, Any] | None = None
    tcp_queries: dict[str, Any] | None = None
    domain_servers: list[dict[str, Any]] | None = None


class PANQoSInterface(PANNamedSourceModel):
    regular_traffic: dict[str, Any] | None = None
    tunnel_traffic: dict[str, Any] | None = None


class PANQoSProfile(PANNamedSourceModel):
    class_bandwidth_type: dict[str, Any] | None = None


class PANZoneProtectionProfile(PANNamedSourceModel):
    description: str | None = None
    flood: dict[str, Any] | None = None
    scan: list[dict[str, Any]] | None = None
    discard_ip_spoof: str | None = None
    discard_strict_source_routing: str | None = None
    discard_loose_source_routing: str | None = None
    tcp_reject_non_syn: str | None = None
    asymmetric_path: str | None = None


class PANMonitorProfile(PANNamedSourceModel):
    interval: str | None = None
    threshold: str | None = None
    action: str | None = None


class PANLLDPProfile(PANNamedSourceModel):
    mode: str | None = None
    snmp_syslog_notification: str | None = None
    option_tlvs: dict[str, Any] | None = None


class PANBFDProfile(PANNamedSourceModel):
    mode: str | None = None
    min_tx_interval: str | None = None
    min_rx_interval: str | None = None
    multiplier: str | None = None
    detection_mode: str | None = None
    hold_time: str | None = None


class PANGlobalProtectClientlessApp(PANNamedSourceModel):
    app_url: str | None = None
    description: str | None = None


class PANGlobalProtectClientlessAppGroup(PANNamedSourceModel):
    members: list[str] | None = None
    description: str | None = None


class PANGlobalProtectMDM(PANNamedSourceModel):
    server: str | None = None
    port: str | None = None
    description: str | None = None


# ----------------------------------------------------------------------
# Device, Auth Server, Certificate & Log Server Profiles
# ----------------------------------------------------------------------


class PANRadiusServerProfile(PANNamedSourceModel):
    protocol: dict[str, Any] | None = None
    timeout: str | None = None
    retries: str | None = None
    servers: list[dict[str, Any]] | None = None
    secret_configured: bool | None = None


class PANLDAPServerProfile(PANNamedSourceModel):
    ldap_type: str | None = None
    ssl: str | None = None
    verify_server_certificate: str | None = None
    base: str | None = None
    bind_dn: str | None = None
    bind_password_configured: bool | None = None
    bind_timelimit: str | None = None
    timelimit: str | None = None
    servers: list[dict[str, Any]] | None = None


class PANTACPlusServerProfile(PANNamedSourceModel):
    protocol: str | None = None
    timeout: str | None = None
    servers: list[dict[str, Any]] | None = None
    secret_configured: bool | None = None


class PANKerberosServerProfile(PANNamedSourceModel):
    servers: list[dict[str, Any]] | None = None


class PANSAMLIdPServerProfile(PANNamedSourceModel):
    entity_id: str | None = None
    sso_url: str | None = None
    slo_url: str | None = None
    sso_binding: str | None = None
    slo_binding: str | None = None
    certificate: str | None = None
    max_clock_skew: str | None = None


class PANMFAServerProfile(PANNamedSourceModel):
    mfa_vendor_type: str | None = None
    mfa_config: dict[str, Any] | None = None
    secret_configured: bool | None = None


class PANCertificate(PANNamedSourceModel):
    common_name: str | None = None
    algorithm: str | None = None
    ca: str | None = None
    expiry_epoch: str | None = None
    not_valid_before: str | None = None
    not_valid_after: str | None = None
    subject: str | None = None
    issuer: str | None = None
    public_key: str | None = None
    private_key_configured: bool | None = None


class PANSSLTLSServiceProfile(PANNamedSourceModel):
    certificate: str | None = None
    protocol_settings: dict[str, Any] | None = None


class PANSyslogServerProfile(PANNamedSourceModel):
    servers: list[dict[str, Any]] | None = None


class PANEmailServerProfile(PANNamedSourceModel):
    servers: list[dict[str, Any]] | None = None


class PANSNMPTrapServerProfile(PANNamedSourceModel):
    version: dict[str, Any] | None = None


class PANHTTPServerProfile(PANNamedSourceModel):
    servers: list[dict[str, Any]] | None = None
    tag_registration: str | None = None


class PANNetflowServerProfile(PANNamedSourceModel):
    template_refresh_rate: dict[str, Any] | None = None
    active_timeout: str | None = None
    export_pan_fields: str | None = None
    servers: list[dict[str, Any]] | None = None


class PANPasswordComplexity(PANNamedSourceModel):
    enabled: str | None = None
    minimum_length: str | None = None
    minimum_uppercase_letters: str | None = None
    minimum_lowercase_letters: str | None = None
    minimum_numeric_letters: str | None = None
    minimum_special_characters: str | None = None
    block_username_inclusion: str | None = None
    new_password_differs_by_characters: str | None = None
    password_history_count: str | None = None


class PANPasswordProfile(PANNamedSourceModel):
    expiration_period: str | None = None
    expiration_warning_period: str | None = None
    post_expiration_grace_period: str | None = None
    post_expiration_admin_login_count: str | None = None


class PANUserIDAgent(PANNamedSourceModel):
    host: str | None = None
    port: str | None = None
    disabled: str | None = None
    ntlm_auth: str | None = None
    ldap_proxy: str | None = None


class PANDeviceObject(PANNamedSourceModel):
    description: str | None = None
    source: str | None = None
    tags: list[str] | None = None


class PANSCPServerProfile(PANNamedSourceModel):
    hostname: str | None = None
    port: str | None = None
    username: str | None = None
    password_configured: bool | None = None
    protocol: str | None = None
    servers: list[dict[str, Any]] | None = None


class PANSSHServerProfile(PANNamedSourceModel):
    hostname: str | None = None
    port: str | None = None
    username: str | None = None
    password_configured: bool | None = None
    protocol: str | None = None
    servers: list[dict[str, Any]] | None = None


class PANUserIDSetting(PANNamedSourceModel):
    setting_type: str | None = None
    settings: dict[str, Any] | None = None


class PANLogSettingCategory(PANNamedSourceModel):
    category: str | None = None
    match_list: list[dict[str, Any]] | None = None
