from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class FGNACPolicy(BaseModel):
    name: str
    vdom: str | None = "root"
    category: str | None = None
    description: str | None = None
    ems_tag: str | None = None
    family: str | None = None
    firewall_address: str | None = None
    fortivoice_tag: str | None = None
    host: str | None = None
    hw_vendor: str | None = None
    hw_version: str | None = None
    mac: str | None = None
    match_period: int | None = None
    match_type: str | None = None
    os: str | None = None
    severity: list[int] = Field(default_factory=list)
    src: str | None = None
    ssid_policy: str | None = None
    status: str | None = None
    sw_version: str | None = None
    switch_fortilink: str | None = None
    switch_group: list[str] = Field(default_factory=list)
    switch_mac_policy: str | None = None
    type: str | None = None
    user: str | None = None
    user_group: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress6TemplateValue(BaseModel):
    name: str
    value: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress6TemplateSegment(BaseModel):
    id: int | None = None
    bits: int | None = None
    exclusive: str | None = None
    name: str | None = None
    values: list[FGAddress6TemplateValue] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress6Template(BaseModel):
    name: str
    vdom: str | None = "root"
    fabric_object: str | None = None
    ip6: str | None = None
    subnet_segment_count: int | None = None
    segments: list[FGAddress6TemplateSegment] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGIPSSettings(BaseModel):
    vdom: str | None = "root"
    ips_packet_quota: int | None = None
    packet_log_history: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGKMIPServerEntry(BaseModel):
    id: int | None = None
    cert: str | None = None
    port: int | None = None
    server: str | None = None
    status: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGKMIPServer(BaseModel):
    name: str
    vdom: str | None = "root"
    interface: str | None = None
    interface_select_method: str | None = None
    password_configured: bool = False
    server_identity_check: str | None = None
    server_list: list[FGKMIPServerEntry] = Field(default_factory=list)
    source_ip: str | None = None
    ssl_min_proto_version: str | None = None
    username: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGKerberosKeytab(BaseModel):
    name: str
    vdom: str | None = "root"
    keytab_configured: bool = False
    ldap_server: list[str] = Field(default_factory=list)
    pac_data: str | None = None
    principal: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterSettings(BaseModel):
    vdom: str | None = "root"
    hostname: str | None = None
    show_filter: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSDNProxy(BaseModel):
    name: str
    vdom: str | None = "root"
    password_configured: bool = False
    server: str | None = None
    server_port: int | None = None
    type: str | None = None
    username: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOnDemandSniffer(BaseModel):
    name: str
    vdom: str | None = "root"
    advanced_filter: str | None = None
    hosts: str | None = None
    interface: str | None = None
    max_packet_count: int | None = None
    non_ip_packet: str | None = None
    ports: list[int] = Field(default_factory=list)
    protocols: list[int] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAffinityInterrupt(BaseModel):
    id: int | None = None
    affinity_cpumask: str | None = None
    default_affinity_cpumask: str | None = None
    interrupt: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSerialPort(BaseModel):
    name: str
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFirewallRegion(BaseModel):
    id: int | None = None
    name: str | None = None
    city: list[int] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGVendorMAC(BaseModel):
    id: int | None = None
    name: str | None = None
    mac_number: int | None = None
    obsolete: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# ----------------------------------------------------------------------
# System / HA / SNMP / DNS / NTP / FortiGuard
# ----------------------------------------------------------------------


class FGSystemGlobal(BaseModel):
    vdom: str | None = "root"
    hostname: str | None = None
    alias: str | None = None
    timezone: str | None = None
    gui_theme: str | None = None
    admin_port: int | None = None
    admin_sport: int | None = None
    admin_ssh_port: int | None = None
    admin_telnet_port: int | None = None
    admintimeout: int | None = None
    admin_https_redirect: str | None = None
    admin_ssh_v1: str | None = None
    admin_scp: str | None = None
    admin_server_cert: str | None = None
    admin_login_max: str | None = None
    admin_lockout_threshold: int | None = None
    admin_lockout_duration: int | None = None
    forticloud_account_enforcement: str | None = None
    admin_password_policy: str | None = None
    password_policy_scope: str | None = None
    management_mode: str | None = None
    switch_controller: str | None = None
    wireless_mode: str | None = None
    vdom_mode: str | None = None
    vdom_admin: str | None = None
    internal_switch_mode: str | None = None
    cfg_save: str | None = None
    revision_backup_on_logout: str | None = None
    pre_login_banner: str | None = None
    post_login_banner: str | None = None
    language: str | None = None
    dh_params: int | None = None
    ldapconntimeout: int | None = None
    remoteauthtimeout: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSystemDNS(BaseModel):
    vdom: str | None = "root"
    primary: str | None = None
    secondary: str | None = None
    protocol: str | None = None
    ssl_certificate: str | None = None
    server_hostname: str | None = None
    domain: list[str] = Field(default_factory=list)
    ip6_primary: str | None = None
    ip6_secondary: str | None = None
    timeout: int | None = None
    retry: int | None = None
    dns_cache_limit: int | None = None
    dns_cache_ttl: int | None = None
    source_ip: str | None = None
    interface_select_method: str | None = None
    interface: list[str] = Field(default_factory=list)
    dns_over_tls: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGNTPServerEntry(BaseModel):
    id: int | None = None
    server: str | None = None
    ntpv3: str | None = None
    authentication: str | None = None
    key_id: int | None = None
    key_configured: bool = False
    interface: str | None = None
    interface_select_method: str | None = None
    ip_type: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSystemNTP(BaseModel):
    vdom: str | None = "root"
    ntpsync: str | None = None
    type: str | None = None
    syncinterval: int | None = None
    server_mode: str | None = None
    source_ip: str | None = None
    source_ip6: str | None = None
    authentication: str | None = None
    key_configured: bool = False
    interface: list[str] = Field(default_factory=list)
    ntpservers: list[FGNTPServerEntry] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGHAMgmtInterface(BaseModel):
    id: int | None = None
    interface: str | None = None
    gateway: str | None = None
    gateway6: str | None = None
    dst: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSystemHA(BaseModel):
    vdom: str | None = "root"
    mode: str | None = None
    group_id: int | None = None
    group_name: str | None = None
    priority: int | None = None
    hbdev: str | None = None
    session_pickup: str | None = None
    session_pickup_connectionless: str | None = None
    session_pickup_expectation: str | None = None
    session_pickup_nat: str | None = None
    session_pickup_delay: str | None = None
    override: str | None = None
    override_wait_time: str | None = None
    schedule: str | None = None
    load_balance_all: str | None = None
    monitor: list[str] = Field(default_factory=list)
    pingserver_monitor_interface: list[str] = Field(default_factory=list)
    secondary_vcluster: list[str] = Field(default_factory=list)
    ha_mgmt_status: str | None = None
    ha_mgmt_interfaces: list[FGHAMgmtInterface] = Field(default_factory=list)
    ha_direct: str | None = None
    unicast_hb: str | None = None
    unicast_hb_peerip: str | None = None
    unicast_hb_netmask: str | None = None
    encryption: str | None = None
    authentication: str | None = None
    password_configured: bool = False
    hb_interval: int | None = None
    hb_lost_threshold: int | None = None
    hello_holddown: int | None = None
    arps: int | None = None
    arps_interval: int | None = None
    sync_packet_balance: int | None = None
    weight: int | None = None
    cpu_threshold: int | None = None
    memory_threshold: int | None = None
    route_ttl: str | None = None
    route_wait: str | None = None
    route_hold: str | None = None
    multicast_ttl: str | None = None
    link_failed_signal: str | None = None
    standalone_mgmt_vdom: str | None = None
    standalone_config_sync: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSNMPSysinfo(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    description: str | None = None
    location: str | None = None
    contact_info: str | None = None
    engine_id: str | None = None
    trap_high_cpu_threshold: int | None = None
    trap_low_memory_threshold: int | None = None
    trap_log_full_threshold: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSNMPCommunityHost(BaseModel):
    id: int | None = None
    ip: str | None = None
    source_ip: str | None = None
    ha_direct: str | None = None
    host_type: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSNMPCommunity(BaseModel):
    id: int | None = None
    vdom: str | None = "root"
    name: str | None = None
    community_configured: bool = False
    status: str | None = None
    query_v1_status: str | None = None
    query_v1_port: int | None = None
    query_v2c_status: str | None = None
    query_v2c_port: int | None = None
    trap_v1_status: str | None = None
    trap_v1_lport: int | None = None
    trap_v1_rport: int | None = None
    trap_v2c_status: str | None = None
    trap_v2c_lport: int | None = None
    trap_v2c_rport: int | None = None
    events: list[str] = Field(default_factory=list)
    mib_view: str | None = None
    vdoms: str | None = None
    hosts: list[FGSNMPCommunityHost] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSNMPUser(BaseModel):
    name: str
    vdom: str | None = "root"
    status: str | None = None
    security_level: str | None = None
    auth_proto: str | None = None
    auth_pwd_configured: bool = False
    priv_proto: str | None = None
    priv_pwd_configured: bool = False
    queries: str | None = None
    query_port: str | None = None
    notify_hosts: list[str] = Field(default_factory=list)
    notify_hosts6: list[str] = Field(default_factory=list)
    notify_port: int | None = None
    source_ip: str | None = None
    source_ipv6: str | None = None
    ha_direct: str | None = None
    events: list[str] = Field(default_factory=list)
    mib_view: str | None = None
    vdoms: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFortiGuard(BaseModel):
    vdom: str | None = "root"
    fortiguard_anycast: str | None = None
    fortiguard_anycast_source: str | None = None
    protocol: str | None = None
    port: int | None = None
    service_account_id: str | None = None
    load_balance_servers: str | None = None
    auto_join_forticloud: int | None = None
    update_server_location: str | None = None
    sandbox_region: str | None = None
    webfilter_sdns_server_ip: str | None = None
    webfilter_sdns_server_port: str | None = None
    webfilter_cache: str | None = None
    webfilter_cache_ttl: int | None = None
    webfilter_timeout: int | None = None
    antispam_cache: str | None = None
    antispam_cache_ttl: int | None = None
    antispam_timeout: int | None = None
    outbreak_prevention_cache: str | None = None
    source_ip: str | None = None
    source_ip6: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    ddns_server_ip: str | None = None
    ddns_server_port: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# ----------------------------------------------------------------------
# Dynamic Routing & Multicast
# ----------------------------------------------------------------------


class FGBGPNeighbor(BaseModel):
    ip: str
    remote_as: int | None = None
    local_as: int | None = None
    interface: str | None = None
    update_source: str | None = None
    description: str | None = None
    shutdown: str | None = None
    bfd: str | None = None
    ebgp_enforce_multihop: str | None = None
    ebgp_multihop_ttl: int | None = None
    next_hop_self: str | None = None
    next_hop_self6: str | None = None
    route_reflector_client: str | None = None
    route_reflector_client6: str | None = None
    soft_reconfiguration: str | None = None
    soft_reconfiguration6: str | None = None
    capability_default_originate: str | None = None
    capability_default_originate6: str | None = None
    capability_graceful_restart: str | None = None
    capability_graceful_restart6: str | None = None
    default_originate_routemap: int | None = None
    route_map_in: str | None = None
    route_map_out: str | None = None
    route_map_in6: str | None = None
    route_map_out6: str | None = None
    prefix_list_in: str | None = None
    prefix_list_out: str | None = None
    prefix_list_in6: str | None = None
    prefix_list_out6: str | None = None
    filter_list_in: str | None = None
    filter_list_out: str | None = None
    distribute_list_in: str | None = None
    distribute_list_out: str | None = None
    neighbor_group: str | None = None
    keep_alive_timer: int | None = None
    holdtime_timer: int | None = None
    connect_timer: int | None = None
    weight: int | None = None
    advertisement_interval: int | None = None
    allowas_in: int | None = None
    allowas_in6: int | None = None
    maximum_prefix: int | None = None
    maximum_prefix6: int | None = None
    passive: str | None = None
    remove_private_as: str | None = None
    remove_private_as6: str | None = None
    as_override: str | None = None
    attribute_unchanged: str | None = None
    activate: str | None = None
    activate6: str | None = None
    additional_path: str | None = None
    additional_path6: str | None = None
    password_configured: bool = False
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGBGPNetwork(BaseModel):
    id: int | None = None
    prefix: str | None = None
    prefix6: str | None = None
    route_map: str | None = None
    backdoor: str | None = None
    network_import_check: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGBGPRedistribute(BaseModel):
    name: str
    status: str | None = None
    route_map: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterBGP(BaseModel):
    vdom: str | None = "root"
    bgp_as: int | None = None
    router_id: str | None = None
    keepalive_timer: int | None = None
    holdtime_timer: int | None = None
    distance_external: int | None = None
    distance_internal: int | None = None
    distance_local: int | None = None
    ebgp_multipath: str | None = None
    ibgp_multipath: str | None = None
    additional_path: str | None = None
    additional_path6: str | None = None
    graceful_restart: str | None = None
    graceful_restart_time: int | None = None
    graceful_stalepath_time: int | None = None
    graceful_update_delay: int | None = None
    scan_time: int | None = None
    always_compare_med: str | None = None
    deterministic_med: str | None = None
    bestpath_as_path_ignore: str | None = None
    bestpath_cmp_routerid: str | None = None
    bestpath_med_confed: str | None = None
    bestpath_med_missing_as_worst: str | None = None
    client_to_client_reflection: str | None = None
    confederation_identifier: str | None = None
    enforce_first_as: str | None = None
    fast_external_failover: str | None = None
    log_neighbour_changes: str | None = None
    network_import_check: str | None = None
    synchronization: str | None = None
    tag_resolve_mode: str | None = None
    neighbors: list[FGBGPNeighbor] = Field(default_factory=list)
    neighbor_groups: list[FGBGPNeighbor] = Field(default_factory=list)
    networks: list[FGBGPNetwork] = Field(default_factory=list)
    networks6: list[FGBGPNetwork] = Field(default_factory=list)
    redistribute: list[FGBGPRedistribute] = Field(default_factory=list)
    redistribute6: list[FGBGPRedistribute] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOSPFArea(BaseModel):
    id: str
    type: str | None = None
    default_cost: int | None = None
    authentication: str | None = None
    shortcut: str | None = None
    nssa_translator_role: str | None = None
    nssa_default_information_originate: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOSPFInterface(BaseModel):
    name: str
    interface: str | None = None
    ip: str | None = None
    authentication: str | None = None
    network_type: str | None = None
    cost: int | None = None
    priority: int | None = None
    hello_interval: int | None = None
    dead_interval: int | None = None
    retransmit_interval: int | None = None
    transmit_delay: int | None = None
    mtu: int | None = None
    mtu_ignore: str | None = None
    bfd: str | None = None
    status: str | None = None
    auth_key_configured: bool = False
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOSPFNetwork(BaseModel):
    id: int | None = None
    prefix: str | None = None
    area: str | None = None
    comments: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOSPFRedistribute(BaseModel):
    name: str
    status: str | None = None
    metric: int | None = None
    metric_type: str | None = None
    tag: int | None = None
    routemap: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterOSPF(BaseModel):
    vdom: str | None = "root"
    router_id: str | None = None
    default_information_originate: str | None = None
    default_information_metric: int | None = None
    default_information_metric_type: str | None = None
    default_information_route_map: str | None = None
    auto_cost_ref_bandwidth: int | None = None
    distance: int | None = None
    distance_external: int | None = None
    distance_inter_area: int | None = None
    distance_intra_area: int | None = None
    abr_type: str | None = None
    rfc1583_compatible: str | None = None
    log_neighbour_changes: str | None = None
    bfd: str | None = None
    restart_mode: str | None = None
    areas: list[FGOSPFArea] = Field(default_factory=list)
    ospf_interfaces: list[FGOSPFInterface] = Field(default_factory=list)
    networks: list[FGOSPFNetwork] = Field(default_factory=list)
    redistribute: list[FGOSPFRedistribute] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterOSPF6(BaseModel):
    vdom: str | None = "root"
    router_id: str | None = None
    default_information_originate: str | None = None
    default_information_metric: int | None = None
    default_information_metric_type: str | None = None
    default_information_route_map: str | None = None
    auto_cost_ref_bandwidth: int | None = None
    abr_type: str | None = None
    log_neighbour_changes: str | None = None
    bfd: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterRIP(BaseModel):
    vdom: str | None = "root"
    version: str | None = None
    default_information_originate: str | None = None
    default_metric: int | None = None
    update_timer: int | None = None
    timeout_timer: int | None = None
    garbage_timer: int | None = None
    max_out_metric: int | None = None
    recv_buffer_size: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGPolicyRoute(BaseModel):
    seq_num: int | None = None
    vdom: str | None = "root"
    address_family: str = "ipv4"
    input_device: list[str] = Field(default_factory=list)
    input_device_negate: str | None = None
    src: list[str] = Field(default_factory=list)
    srcaddr: list[str] = Field(default_factory=list)
    src_negate: str | None = None
    dst: list[str] = Field(default_factory=list)
    dstaddr: list[str] = Field(default_factory=list)
    dst_negate: str | None = None
    action: str | None = None
    protocol: int | None = None
    start_port: int | None = None
    end_port: int | None = None
    start_source_port: int | None = None
    end_source_port: int | None = None
    gateway: str | None = None
    output_device: str | None = None
    tos: int | None = None
    tos_mask: int | None = None
    status: str | None = None
    comments: str | None = None
    internet_service_id: list[str] = Field(default_factory=list)
    internet_service_custom: list[str] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGPrefixListRule(BaseModel):
    id: int | None = None
    action: str | None = None
    prefix: str | None = None
    prefix6: str | None = None
    ge: int | None = None
    le: int | None = None
    flags: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGPrefixList(BaseModel):
    name: str
    vdom: str | None = "root"
    address_family: str = "ipv4"
    comments: str | None = None
    rules: list[FGPrefixListRule] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouteMapRule(BaseModel):
    id: int | None = None
    action: str | None = None
    match_as_path: str | None = None
    match_community: str | None = None
    match_community_exact: str | None = None
    match_interface: str | None = None
    match_ip_address: str | None = None
    match_ip_nexthop: str | None = None
    match_ip6_address: str | None = None
    match_ip6_nexthop: str | None = None
    match_metric: int | None = None
    match_origin: str | None = None
    match_route_type: str | None = None
    match_tag: int | None = None
    match_vrf: int | None = None
    set_aggregator_as: str | None = None
    set_aggregator_ip: str | None = None
    set_aspath: str | None = None
    set_aspath_action: str | None = None
    set_atomic_aggregate: str | None = None
    set_community: str | None = None
    set_community_additive: str | None = None
    set_community_delete: str | None = None
    set_dampening_max_suppress: str | None = None
    set_extcommunity_rt: str | None = None
    set_extcommunity_soo: str | None = None
    set_ip_nexthop: str | None = None
    set_ip6_nexthop: str | None = None
    set_ip6_nexthop_local: str | None = None
    set_local_preference: int | None = None
    set_metric: int | None = None
    set_metric_type: str | None = None
    set_origin: str | None = None
    set_origin_as: int | None = None
    set_originator_id: str | None = None
    set_route_tag: str | None = None
    set_tag: int | None = None
    set_weight: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouteMap(BaseModel):
    name: str
    vdom: str | None = "root"
    comments: str | None = None
    rules: list[FGRouteMapRule] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGASPathListRule(BaseModel):
    id: int | None = None
    action: str | None = None
    regexp: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGASPathList(BaseModel):
    name: str
    vdom: str | None = "root"
    rules: list[FGASPathListRule] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGCommunityListRule(BaseModel):
    id: int | None = None
    action: str | None = None
    match: str | None = None
    regexp: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGCommunityList(BaseModel):
    name: str
    vdom: str | None = "root"
    type: str | None = None
    rules: list[FGCommunityListRule] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGMulticastInterface(BaseModel):
    name: str
    pim_mode: str | None = None
    dr_priority: int | None = None
    hello_interval: int | None = None
    hello_holdtime: int | None = None
    igmp_version: int | None = None
    ttl_threshold: int | None = None
    passive: str | None = None
    multicast_flow: str | None = None
    static_group: str | None = None
    rpf_nbr_fail_back: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRouterMulticast(BaseModel):
    vdom: str | None = "root"
    multicast_routing: str | None = None
    route_limit: int | None = None
    route_threshold: int | None = None
    interfaces: list[FGMulticastInterface] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSystemIPAM(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    server_type: str | None = None
    pool_subnet: str | None = None
    manage_lan_addresses: str | None = None
    manage_lan_extension_addresses: str | None = None
    manage_ssid_addresses: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFortiExtender(BaseModel):
    name: str
    vdom: str | None = "root"
    id: int | None = None
    sn: str | None = None
    authorized: str | None = None
    admin: str | None = None
    ext_name: str | None = None
    description: str | None = None
    role: str | None = None
    mode: str | None = None
    wan_extension: str | None = None
    lan_extension: str | None = None
    device_id: str | None = None
    extension_type: str | None = None
    profile: str | None = None
    quota_limit: int | None = None
    billing_start_day: int | None = None
    override_allowaccess: str | None = None
    login_password_change: str | None = None
    login_password_configured: bool = False
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# ----------------------------------------------------------------------
# Extended Policies, Shapers & Load Balance Monitors
# ----------------------------------------------------------------------


class FGProxyPolicy(BaseModel):
    policy_id: int | None = None
    vdom: str | None = "root"
    uuid: str | None = None
    name: str | None = None
    proxy: str | None = None
    status: str | None = None
    srcintf: list[str] = Field(default_factory=list)
    dstintf: list[str] = Field(default_factory=list)
    srcaddr: list[str] = Field(default_factory=list)
    dstaddr: list[str] = Field(default_factory=list)
    srcaddr6: list[str] = Field(default_factory=list)
    dstaddr6: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    action: str | None = None
    schedule: str | None = None
    logtraffic: str | None = None
    logtraffic_start: str | None = None
    comments: str | None = None
    groups: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    poolname: list[str] = Field(default_factory=list)
    utm_status: str | None = None
    profile_type: str | None = None
    profile_group: str | None = None
    profile_protocol_options: str | None = None
    av_profile: str | None = None
    webfilter_profile: str | None = None
    emailfilter_profile: str | None = None
    dlp_profile: str | None = None
    file_filter_profile: str | None = None
    ips_sensor: str | None = None
    application_list: str | None = None
    icap_profile: str | None = None
    cifs_profile: str | None = None
    waf_profile: str | None = None
    ssh_filter_profile: str | None = None
    ssl_ssh_profile: str | None = None
    replacemsg_override_group: str | None = None
    transparent: str | None = None
    webcache: str | None = None
    webcache_https: str | None = None
    http_tunnel_auth: str | None = None
    srcaddr_negate: str | None = None
    dstaddr_negate: str | None = None
    service_negate: str | None = None
    internet_service: str | None = None
    internet_service_name: list[str] = Field(default_factory=list)
    internet_service_group: list[str] = Field(default_factory=list)
    internet_service_custom: list[str] = Field(default_factory=list)
    access_proxy: list[str] = Field(default_factory=list)
    access_proxy6: list[str] = Field(default_factory=list)
    disclaimer: str | None = None
    redirect_url: str | None = None
    decryption_traffic_mirror: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAuthPolicy(BaseModel):
    policy_id: int | None = None
    vdom: str | None = "root"
    name: str | None = None
    status: str | None = None
    srcintf: list[str] = Field(default_factory=list)
    srcaddr: list[str] = Field(default_factory=list)
    dstaddr: list[str] = Field(default_factory=list)
    srcaddr6: list[str] = Field(default_factory=list)
    dstaddr6: list[str] = Field(default_factory=list)
    service: str | None = None
    groups: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    active_auth_method: str | None = None
    sso_auth_method: str | None = None
    web_auth_cookie: str | None = None
    http_auth_type: str | None = None
    srcaddr_negate: str | None = None
    dstaddr_negate: str | None = None
    comments: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGTrafficShaper(BaseModel):
    name: str
    vdom: str | None = "root"
    guaranteed_bandwidth: int | None = None
    maximum_bandwidth: int | None = None
    bandwidth_unit: str | None = None
    priority: str | None = None
    per_policy: str | None = None
    diffserv: str | None = None
    diffservcode: str | None = None
    dscp_marking_method: str | None = None
    exceed_bandwidth: str | None = None
    exceed_dscp: str | None = None
    maximum_dscp: str | None = None
    overhead: int | None = None
    cos_marking_method: int | None = None
    cos: str | None = None
    exceed_cos: str | None = None
    maximum_cos: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLDBMonitor(BaseModel):
    name: str
    vdom: str | None = "root"
    type: str | None = None
    interval: int | None = None
    timeout: int | None = None
    retry: int | None = None
    port: int | None = None
    src_ip: str | None = None
    http_get: str | None = None
    http_match: str | None = None
    http_max_redirects: int | None = None
    dns_protocol: str | None = None
    dns_request_domain: str | None = None
    dns_match_ip: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# ----------------------------------------------------------------------
# Security Profiles
# ----------------------------------------------------------------------


class FGAVProtocolConfig(BaseModel):
    protocol: str
    av_scan: str | None = None
    options: str | None = None
    archive_block: list[str] = Field(default_factory=list)
    archive_log: list[str] = Field(default_factory=list)
    outbreak_prevention: str | None = None
    quarantine: str | None = None
    emulator: str | None = None
    executables: str | None = None
    external_blocklist: str | None = None
    content_disarm: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAntivirusProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    feature_set: str | None = None
    inspection_mode: str | None = None
    ftgd_analytics: str | None = None
    analytics_db: str | None = None
    mobile_malware_db: str | None = None
    av_virus_log: str | None = None
    av_block_log: str | None = None
    extended_log: str | None = None
    scan_mode: str | None = None
    replacemsg_group: str | None = None
    ems_threat_feed: str | None = None
    outbreak_prevention: str | None = None
    outbreak_prevention_archive_scan: str | None = None
    protocols: list[FGAVProtocolConfig] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWebFilterFTGDFilter(BaseModel):
    id: int | None = None
    category: int | None = None
    action: str | None = None
    log: str | None = None
    warning_prompt: str | None = None
    warn_duration: str | None = None
    auth_usr_grp: list[str] = Field(default_factory=list)
    override_replacemsg: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWebFilterProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    feature_set: str | None = None
    inspection_mode: str | None = None
    options: list[str] = Field(default_factory=list)
    replacemsg_group: str | None = None
    ovrd_perm: str | None = None
    post_action: str | None = None
    log_all_url: str | None = None
    web_content_log: str | None = None
    web_url_log: str | None = None
    web_invalid_domain_log: str | None = None
    web_ftgd_err_log: str | None = None
    web_ftgd_quota_usage: str | None = None
    extended_log: str | None = None
    wisp: str | None = None
    wisp_algorithm: str | None = None
    https_replacemsg: str | None = None
    urlfilter_table: int | None = None
    block_invalid_url: str | None = None
    safe_search: list[str] = Field(default_factory=list)
    youtube_restrict: str | None = None
    ftgd_options: list[str] = Field(default_factory=list)
    ftgd_ovrd: list[str] = Field(default_factory=list)
    ftgd_filters: list[FGWebFilterFTGDFilter] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGURLFilterEntry(BaseModel):
    id: int | None = None
    url: str | None = None
    type: str | None = None
    action: str | None = None
    status: str | None = None
    exempt: str | None = None
    web_proxy_profile: str | None = None
    referrer_host: str | None = None
    dns_address_family: str | None = None
    antiphish_action: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGURLFilterTable(BaseModel):
    id: int | None = None
    vdom: str | None = "root"
    name: str | None = None
    comment: str | None = None
    one_arm_ips_urlfilter: str | None = None
    ip_addr_block: str | None = None
    ip4_mapped_ip6: str | None = None
    entries: list[FGURLFilterEntry] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWebFilterLocalCategory(BaseModel):
    name: str
    vdom: str | None = "root"
    id: int | None = None
    status: str | None = None
    desc: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWebFilterLocalRating(BaseModel):
    url: str
    vdom: str | None = "root"
    rating: list[int] = Field(default_factory=list)
    status: str | None = None
    comment: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWebFilterOverride(BaseModel):
    id: int | None = None
    vdom: str | None = "root"
    status: str | None = None
    user: str | None = None
    user_group: str | None = None
    ip: str | None = None
    ip6: str | None = None
    new_profile: str | None = None
    old_profile: str | None = None
    scope: str | None = None
    expires: str | None = None
    initiator: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGDNSFilterFTGDFilter(BaseModel):
    id: int | None = None
    category: int | None = None
    action: str | None = None
    log: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGDNSFilterProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    block_action: str | None = None
    redirect_portal: str | None = None
    redirect_portal6: str | None = None
    block_botnet: str | None = None
    safe_search: str | None = None
    youtube_restrict: str | None = None
    log_all_domain: str | None = None
    sdns_ftgd_err_log: str | None = None
    sdns_domain_log: str | None = None
    strip_ech: str | None = None
    external_ip_blocklist: list[str] = Field(default_factory=list)
    transparent_dns_database: list[str] = Field(default_factory=list)
    domain_filter_table: int | None = None
    ftgd_options: list[str] = Field(default_factory=list)
    ftgd_filters: list[FGDNSFilterFTGDFilter] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGApplicationListEntry(BaseModel):
    id: int | None = None
    category: list[int] = Field(default_factory=list)
    application: list[int] = Field(default_factory=list)
    risk: list[int] = Field(default_factory=list)
    popularity: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    vendor: list[str] = Field(default_factory=list)
    technology: list[str] = Field(default_factory=list)
    behavior: list[str] = Field(default_factory=list)
    action: str | None = None
    log: str | None = None
    log_packet: str | None = None
    per_ip_shaper: str | None = None
    session_ttl: str | None = None
    shaper: str | None = None
    shaper_reverse: str | None = None
    quarantine: str | None = None
    quarantine_expiry: str | None = None
    quarantine_log: str | None = None
    sub_category: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGApplicationList(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    options: list[str] = Field(default_factory=list)
    other_application_action: str | None = None
    other_application_log: str | None = None
    unknown_application_action: str | None = None
    unknown_application_log: str | None = None
    enforce_default_app_port: str | None = None
    default_network_services: str | None = None
    deep_app_inspection: str | None = None
    extended_log: str | None = None
    replacemsg_group: str | None = None
    control_default_network_services: str | None = None
    entries: list[FGApplicationListEntry] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFileFilterRule(BaseModel):
    name: str
    comment: str | None = None
    protocol: list[str] = Field(default_factory=list)
    file_type: list[str] = Field(default_factory=list)
    action: str | None = None
    direction: str | None = None
    password_protected: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFileFilterProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    feature_set: str | None = None
    replacemsg_group: str | None = None
    log: str | None = None
    extended_log: str | None = None
    scan_archive_contents: str | None = None
    rules: list[FGFileFilterRule] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGEmailFilterProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    feature_set: str | None = None
    replacemsg_group: str | None = None
    spam_filtering: str | None = None
    options: list[str] = Field(default_factory=list)
    spam_log: str | None = None
    spam_log_fortiguard_response: str | None = None
    external: str | None = None
    spam_bword_table: int | None = None
    spam_bword_threshold: int | None = None
    spam_bwl_table: int | None = None
    spam_mheader_table: int | None = None
    spam_ipbwl_table: int | None = None
    spam_iptrust_table: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGVoIPProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    feature_set: str | None = None
    sip_status: str | None = None
    sip_rtp: str | None = None
    sip_strict_register: str | None = None
    sip_invite_rate: int | None = None
    sip_register_rate: int | None = None
    sip_log_violations: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWAFProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    extended_log: str | None = None
    external: str | None = None
    replacemsg_group: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLSSHProtocolConfig(BaseModel):
    protocol: str
    ports: list[int] = Field(default_factory=list)
    status: str | None = None
    client_certificate: str | None = None
    unsupported_ssl_cipher: str | None = None
    unsupported_ssl_negotiation: str | None = None
    unsupported_ssl_version: str | None = None
    expired_server_cert: str | None = None
    revoked_server_cert: str | None = None
    untrusted_server_cert: str | None = None
    cert_validation_timeout: str | None = None
    cert_validation_failure: str | None = None
    sni_server_cert_check: str | None = None
    min_allowed_ssl_version: str | None = None
    quic: str | None = None
    proxy_after_tcp_handshake: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLSSHProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    caname: str | None = None
    untrusted_caname: list[str] = Field(default_factory=list)
    server_cert_mode: str | None = None
    server_cert: str | None = None
    use_ssl_server: str | None = None
    ssl_exemption_ip_rating: str | None = None
    ssl_exemption_log: str | None = None
    ssl_anomaly_log: str | None = None
    ssl_negotiation_log: str | None = None
    ssl_server_cert_log: str | None = None
    ssl_handshake_log: str | None = None
    rpc_over_http: str | None = None
    mapi_over_https: str | None = None
    supported_alpn: str | None = None
    ech_outer_sni: str | None = None
    protocols: list[FGSSLSSHProtocolConfig] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# ----------------------------------------------------------------------
# User & Auth Extensions
# ----------------------------------------------------------------------


class FGLDAPServer(BaseModel):
    name: str
    vdom: str | None = "root"
    server: str | None = None
    secondary_server: str | None = None
    tertiary_server: str | None = None
    server_identity_check: str | None = None
    port: int | None = None
    cnid: str | None = None
    dn: str | None = None
    type: str | None = None
    username: str | None = None
    password_configured: bool = False
    group_member_check: str | None = None
    group_search_base: str | None = None
    group_object_filter: str | None = None
    group_filter: str | None = None
    secure: str | None = None
    ca_cert: str | None = None
    client_cert: str | None = None
    client_cert_auth: str | None = None
    member_attr: str | None = None
    account_key_processing: str | None = None
    account_key_filter: str | None = None
    account_key_upn_san: int | None = None
    source_ip: str | None = None
    source_port: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    two_factor: str | None = None
    two_factor_authentication: str | None = None
    two_factor_notification: str | None = None
    two_factor_filter: str | None = None
    password_expiry_warning: str | None = None
    password_renewal: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRADIUSServer(BaseModel):
    name: str
    vdom: str | None = "root"
    server: str | None = None
    secret_configured: bool = False
    secondary_server: str | None = None
    secondary_secret_configured: bool = False
    tertiary_server: str | None = None
    tertiary_secret_configured: bool = False
    timeout: int | None = None
    radius_port: int | None = None
    auth_type: str | None = None
    nas_ip: str | None = None
    nas_ip6: str | None = None
    nas_id: str | None = None
    nas_id_type: str | None = None
    all_usergroup: str | None = None
    use_management_vdom: str | None = None
    sso_attribute: str | None = None
    sso_attribute_key: str | None = None
    rsso: str | None = None
    rsso_radius_server_port: str | None = None
    rsso_radius_response: str | None = None
    rsso_validate_request_secret: str | None = None
    source_ip: str | None = None
    source_ip6: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    h3c_compatibility: str | None = None
    password_renewal: str | None = None
    password_encoding: str | None = None
    acct_all_servers: str | None = None
    acct_interim_interval: int | None = None
    switch_controller_acct_fast_framedip_detect: str | None = None
    transport_protocol: str | None = None
    ca_cert: str | None = None
    client_cert: str | None = None
    tls_min_proto_version: str | None = None
    server_identity_check: str | None = None
    radius_class: list[str] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGTACACSServer(BaseModel):
    name: str
    vdom: str | None = "root"
    server: str | None = None
    secret_configured: bool = False
    secondary_server: str | None = None
    secondary_secret_configured: bool = False
    tertiary_server: str | None = None
    tertiary_secret_configured: bool = False
    port: int | None = None
    authen_type: str | None = None
    authorization: str | None = None
    source_ip: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFSSOServer(BaseModel):
    name: str
    vdom: str | None = "root"
    server: str | None = None
    port: int | None = None
    password_configured: bool = False
    server2: str | None = None
    port2: int | None = None
    server3: str | None = None
    port3: int | None = None
    server4: str | None = None
    port4: int | None = None
    server5: str | None = None
    port5: int | None = None
    ldap_server: str | None = None
    ldap_poll: str | None = None
    ldap_poll_interval: str | None = None
    ldap_poll_filter: str | None = None
    group_poll_interval: int | None = None
    user_info_server: str | None = None
    ssl: str | None = None
    ssl_trusted_cert: str | None = None
    ssl_server_host_ip_check: str | None = None
    source_ip: str | None = None
    source_ip6: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    type: str | None = None
    logon_timeout: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFSSOPolling(BaseModel):
    id: int | None = None
    vdom: str | None = "root"
    status: str | None = None
    server: str | None = None
    default_domain: str | None = None
    user: str | None = None
    password_configured: bool = False
    ldap_server: str | None = None
    poll_frequency: int | None = None
    port: int | None = None
    logon_history: str | None = None
    smb_ntlmv1_auth: str | None = None
    smbv1: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFortiToken(BaseModel):
    serial_number: str
    vdom: str | None = "root"
    status: str | None = None
    comments: str | None = None
    license: str | None = None
    os_ver: str | None = None
    reg_id: str | None = None
    activation_expire: int | None = None
    seed_configured: bool = False
    activation_code_configured: bool = False
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGUserSetting(BaseModel):
    vdom: str | None = "root"
    auth_type: str | None = None
    auth_cert: str | None = None
    auth_ca_cert: str | None = None
    auth_secure_http: str | None = None
    auth_http_basic: str | None = None
    auth_ssl_allow_renegotiation: str | None = None
    auth_timeout: int | None = None
    auth_timeout_type: str | None = None
    auth_portal_timeout: int | None = None
    auth_blackout_time: int | None = None
    auth_invalid_max: str | None = None
    auth_lockout_threshold: str | None = None
    auth_lockout_duration: str | None = None
    per_policy_disclaimer: str | None = None
    radius_ses_timeout_act: str | None = None
    auth_on_demand: str | None = None
    auth_ssl_min_proto_version: str | None = None
    auth_ssl_max_proto_version: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGPasswordPolicy(BaseModel):
    name: str
    vdom: str | None = "root"
    expire_status: str | None = None
    expire_days: int | None = None
    warn_days: str | None = None
    min_lower_case_letter: int | None = None
    min_upper_case_letter: int | None = None
    min_non_alphanumeric: int | None = None
    min_number: int | None = None
    minimum_length: int | None = None
    min_change_characters: int | None = None
    change_4_characters: str | None = None
    reuse_password: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSystemPasswordPolicy(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    apply_to: list[str] = Field(default_factory=list)
    minimum_length: int | None = None
    min_lower_case_letter: int | None = None
    min_upper_case_letter: int | None = None
    min_non_alphanumeric: int | None = None
    min_number: int | None = None
    min_change_characters: int | None = None
    expire_status: str | None = None
    expire_day: int | None = None
    reuse_password: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# ----------------------------------------------------------------------
# WiFi, Switch & Logging
# ----------------------------------------------------------------------


class FGWirelessVAP(BaseModel):
    name: str
    vdom: str | None = "root"
    ssid: str | None = None
    status: str | None = None
    broadcast_ssid: str | None = None
    security: str | None = None
    encrypt: str | None = None
    auth: str | None = None
    passphrase_configured: bool = False
    radius_server: str | None = None
    radius_mac_auth: str | None = None
    radius_mac_auth_server: str | None = None
    usergroup: list[str] = Field(default_factory=list)
    selected_usergroups: list[str] = Field(default_factory=list)
    security_exempt_list: list[str] = Field(default_factory=list)
    address_group: list[str] = Field(default_factory=list)
    local_standalone: str | None = None
    local_standalone_nat: str | None = None
    local_bridging: str | None = None
    local_authentication: str | None = None
    intra_vap_privacy: str | None = None
    schedule: str | None = None
    vlanid: int | None = None
    max_clients: int | None = None
    max_clients_ap: int | None = None
    portal_type: str | None = None
    portal_message_override_group: str | None = None
    external_web: str | None = None
    external_logout: str | None = None
    captive_portal_ac_name: str | None = None
    pmf: str | None = None
    okc: str | None = None
    voice_enterprise: str | None = None
    fast_bss_transition: str | None = None
    dynamic_vlan: str | None = None
    vlan_pooling: str | None = None
    multicast_enhance: str | None = None
    igmp_snooping: str | None = None
    dhcp_address_enforcement: str | None = None
    mpsk: str | None = None
    mpsk_profile: str | None = None
    quarantine: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWirelessWTP(BaseModel):
    wtp_id: str
    vdom: str | None = "root"
    name: str | None = None
    index: int | None = None
    admin: str | None = None
    wtp_profile: str | None = None
    wtp_mode: str | None = None
    location: str | None = None
    comment: str | None = None
    login_passwd_change: str | None = None
    login_passwd_configured: bool = False
    override_ip_fragment_preventing: str | None = None
    override_wan_port_mode: str | None = None
    wan_port_mode: str | None = None
    override_lan: str | None = None
    override_led_state: str | None = None
    led_state: str | None = None
    override_allowaccess: str | None = None
    allowaccess: str | None = None
    image_download: str | None = None
    mesh_bridge_enable: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWirelessWTPProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    login_passwd_change: str | None = None
    login_passwd_configured: bool = False
    allowaccess: list[str] = Field(default_factory=list)
    dtls_policy: str | None = None
    max_clients: str | None = None
    handoff_rssi: str | None = None
    handoff_sta_thresh: str | None = None
    handoff_roaming: str | None = None
    ap_country: str | None = None
    ip_fragment_preventing: str | None = None
    tun_mtu_uplink: str | None = None
    tun_mtu_downlink: str | None = None
    split_tunneling_acl_path: str | None = None
    split_tunneling_acl_local_ap_subnet: str | None = None
    energy_efficient_ethernet: str | None = None
    led_state: str | None = None
    poe_mode: str | None = None
    wan_port_mode: str | None = None
    lldp: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWirelessWIDSProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    sensor_mode: str | None = None
    ap_scan: str | None = None
    ap_scan_passive: str | None = None
    wireless_bridge: str | None = None
    deauth_broadcast: str | None = None
    null_ssid_probe_resp: str | None = None
    long_duration_attack: str | None = None
    invalid_mac_oui: str | None = None
    weak_wep_iv: str | None = None
    auth_frame_flood: str | None = None
    assoc_frame_flood: str | None = None
    reassoc_flood: str | None = None
    probe_flood: str | None = None
    disassoc_flood: str | None = None
    deauth_flood: str | None = None
    eapol_start_flood: str | None = None
    eapol_logoff_flood: str | None = None
    eapol_succ_flood: str | None = None
    eapol_fail_flood: str | None = None
    asleap_attack: str | None = None
    airjack: str | None = None
    fata_jack: str | None = None
    omerta: str | None = None
    wellenreiter: str | None = None
    netstumbler: str | None = None
    rogue_scan: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGManagedSwitchPort(BaseModel):
    port_name: str
    switch_id: str | None = None
    speed: str | None = None
    status: str | None = None
    poe_status: str | None = None
    poe_pre_standard_detection: str | None = None
    poe_max_power: int | None = None
    vlan: str | None = None
    allowed_vlans: list[str] = Field(default_factory=list)
    untagged_vlans: list[str] = Field(default_factory=list)
    allowed_vlans_all: str | None = None
    stp_state: str | None = None
    stp_root_guard: str | None = None
    stp_bpdu_guard: str | None = None
    edge_port: str | None = None
    loop_guard: str | None = None
    dhcp_snooping: str | None = None
    igmp_snooping: str | None = None
    igmp_fast_leave: str | None = None
    qos_policy: str | None = None
    port_security_policy: str | None = None
    lldp_profile: str | None = None
    lldp_status: str | None = None
    type: str | None = None
    trunk: str | None = None
    description: str | None = None
    access_mode: str | None = None
    fortilink_port: str | None = None
    export_tags: list[str] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGManagedSwitch(BaseModel):
    switch_id: str
    vdom: str | None = "root"
    name: str | None = None
    sn: str | None = None
    fsw_wan1_peer: str | None = None
    fsw_wan1_admin: str | None = None
    fsw_wan2_peer: str | None = None
    fsw_wan2_admin: str | None = None
    version: str | None = None
    poe_pre_standard_detection: str | None = None
    poe_detection_type: str | None = None
    max_allowed_trunk_members: int | None = None
    dynamic_capability: int | None = None
    directly_connected: str | None = None
    switch_profile: str | None = None
    override_snmp_sysinfo: str | None = None
    override_snmp_community: str | None = None
    override_snmp_user: str | None = None
    description: str | None = None
    type: str | None = None
    owner_vdom: str | None = None
    mclag_igmp_snooping_aware: str | None = None
    ports: list[FGManagedSwitchPort] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSyslogSetting(BaseModel):
    syslog_name: str = "syslogd"
    vdom: str | None = "root"
    status: str | None = None
    server: str | None = None
    mode: str | None = None
    port: int | None = None
    facility: str | None = None
    source_ip: str | None = None
    format: str | None = None
    priority: str | None = None
    max_log_rate: int | None = None
    enc_algorithm: str | None = None
    ssl_min_proto_version: str | None = None
    certificate: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLogMemorySetting(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    diskfull: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLogDiskSetting(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    ips_archive: str | None = None
    maximum_log_age: int | None = None
    upload: str | None = None
    upload_destination: str | None = None
    upload_ip: str | None = None
    upload_user: str | None = None
    upload_password_configured: bool = False
    upload_folder: str | None = None
    upload_format: str | None = None
    upload_time: int | None = None
    upload_ssl_conn: str | None = None
    diskfull: str | None = None
    log_quota: str | None = None
    dlp_archive_quota: str | None = None
    report_quota: str | None = None
    max_log_file_size: int | None = None
    roll_schedule: str | None = None
    roll_day: int | None = None
    roll_time: str | None = None
    full_first_warning_threshold: int | None = None
    full_second_warning_threshold: int | None = None
    full_final_warning_threshold: int | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLogSetting(BaseModel):
    vdom: str | None = "root"
    resolve_ip: str | None = None
    resolve_port: str | None = None
    log_user_in_upper: str | None = None
    fwpolicy_implicit_log: str | None = None
    fwpolicy6_implicit_log: str | None = None
    log_invalid_packet: str | None = None
    local_in_allow: str | None = None
    local_in_deny_unicast: str | None = None
    local_in_deny_broadcast: str | None = None
    local_out: str | None = None
    local_out_ioc_detection: str | None = None
    daemon_log: str | None = None
    neighbor_event: str | None = None
    expolicy_implicit_log: str | None = None
    faz_override: str | None = None
    syslog_override: str | None = None
    rest_api_set: str | None = None
    rest_api_get: str | None = None
    custom_log_fields: list[str] = Field(default_factory=list)
    brief_traffic_format: str | None = None
    user_anonymize: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGThreatWeightLevel(BaseModel):
    low: int | None = None
    medium: int | None = None
    high: int | None = None
    critical: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGThreatWeightIPS(BaseModel):
    info_severity: str | None = None
    low_severity: str | None = None
    medium_severity: str | None = None
    high_severity: str | None = None
    critical_severity: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGThreatWeightMalware(BaseModel):
    virus_infected: str | None = None
    virus_file_type_executable: str | None = None
    virus_outbreak_prevention: str | None = None
    virus_scan_error: str | None = None
    botnet_connection: str | None = None
    command_blocked: str | None = None
    file_blocked: str | None = None
    oversize: str | None = None
    switch_proto: str | None = None
    mimefragmented: str | None = None
    content_disarm: str | None = None
    fortisandbox: str | None = None
    fortindr: str | None = None
    malware_list: str | None = None
    ems_threat_feed: str | None = None
    fsa_malicious: str | None = None
    fsa_high_risk: str | None = None
    fsa_medium_risk: str | None = None
    inline_block: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGThreatWeightCategoryEntry(BaseModel):
    id: int | None = None
    category: int | None = None
    level: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLogThreatWeight(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    blocked_connection: str | None = None
    failed_connection: str | None = None
    url_block_detected: str | None = None
    url_block_detect: str | None = None
    botnet_connection_detected: str | None = None
    level: FGThreatWeightLevel | None = None
    ips: FGThreatWeightIPS | None = None
    malware: FGThreatWeightMalware | None = None
    web: list[FGThreatWeightCategoryEntry] = Field(default_factory=list)
    application: list[FGThreatWeightCategoryEntry] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGUserGuest(BaseModel):
    id: str
    vdom: str | None = "root"
    user_id: str | None = None
    type: str | None = None
    sponsor: str | None = None
    company: str | None = None
    email: str | None = None
    mobile_phone: str | None = None
    expiration: int | None = None
    password_configured: bool = False
    comment: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSwitchPortPolicy(BaseModel):
    name: str
    vdom: str | None = "root"
    description: str | None = None
    fortilink: str | None = None
    qos_policy: str | None = None
    vlan_policy: str | None = None
    bounce_port_link: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSwitchLLDPProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    med_tlvs: list[str] = Field(default_factory=list)
    auto_isl: str | None = None
    auto_isl_hello_timer: int | None = None
    auto_isl_receive_timeout: int | None = None
    auto_isl_port_group: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSwitchQoSPolicy(BaseModel):
    name: str
    vdom: str | None = "root"
    default_cos: int | None = None
    queue_policy: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSwitchVLANPolicy(BaseModel):
    name: str
    vdom: str | None = "root"
    description: str | None = None
    fortilink: str | None = None
    vlan: str | None = None
    allowed_vlans: list[str] = Field(default_factory=list)
    untagged_vlans: list[str] = Field(default_factory=list)
    allowed_vlans_all: str | None = None
    discard_mode: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGCertificate(BaseModel):
    """Public X.509 certificate metadata from vpn certificate {local,ca,remote}; private keys are never stored."""

    name: str
    store: Literal["local", "ca", "remote"]
    vdom: str | None = "root"
    certificate: str | None = None
    private_key_configured: bool = False
    password_configured: bool = False
    ca_identifier: str | None = None
    comments: str | None = None
    source: str | None = None
    source_ip: str | None = None
    range: str | None = None
    scep_url: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLocalInPolicy(BaseModel):
    policy_id: int | None = None
    vdom: str | None = "root"
    address_family: Literal["ipv4", "ipv6"] = "ipv4"
    uuid: str | None = None
    intf: list[str] = Field(default_factory=list)
    srcaddr: list[str] = Field(default_factory=list)
    dstaddr: list[str] = Field(default_factory=list)
    srcaddr_negate: str | None = None
    dstaddr_negate: str | None = None
    action: str | None = None
    service: list[str] = Field(default_factory=list)
    service_negate: str | None = None
    schedule: str | None = None
    status: str | None = None
    comments: str | None = None
    virtual_patch: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGFortiAnalyzerSetting(BaseModel):
    target_name: str = "fortianalyzer"
    vdom: str | None = "root"
    status: str | None = None
    server: str | None = None
    source_ip: str | None = None
    upload_option: str | None = None
    reliable: str | None = None
    enc_algorithm: str | None = None
    ssl_min_proto_version: str | None = None
    certificate: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGLogFortiGuardSetting(BaseModel):
    vdom: str | None = "root"
    status: str | None = None
    upload_option: str | None = None
    upload_interval: str | None = None
    upload_day: str | None = None
    upload_time: str | None = None
    enc_algorithm: str | None = None
    interface: str | None = None
    interface_select_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSystemStorage(BaseModel):
    name: str
    vdom: str | None = "root"
    status: str | None = None
    media_status: str | None = None
    order: int | None = None
    partition: str | None = None
    device: str | None = None
    size: int | None = None
    usage: str | None = None
    wanopt_mode: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSAMLServer(BaseModel):
    name: str
    vdom: str | None = "root"
    cert: str | None = None
    entity_id: str | None = None
    single_sign_on_url: str | None = None
    single_logout_url: str | None = None
    idp_entity_id: str | None = None
    idp_single_sign_on_url: str | None = None
    idp_single_logout_url: str | None = None
    idp_cert: str | None = None
    user_name: str | None = None
    group_name: str | None = None
    digest_method: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
