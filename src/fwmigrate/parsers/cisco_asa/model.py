from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CiscoInterface(BaseModel):
    name: str
    interface_type: Optional[str] = None
    parent_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    port_channel_id: Optional[int] = None
    channel_group: Optional[int] = None
    channel_group_mode: Optional[str] = None
    redundant_interface_members: List[str] = Field(default_factory=list)
    bridge_group: Optional[int] = None
    bvi_id: Optional[int] = None
    mtu: Optional[int] = None
    routing_context: Optional[str] = None
    vrf: Optional[str] = None
    administrative_state: Optional[str] = None
    nameif: Optional[str] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    ip_mode: Optional[str] = None
    standby_ip: Optional[str] = None
    dhcp_setroute: bool = False
    ipv6_addresses: List["CiscoIPv6Address"] = Field(default_factory=list)
    ipv6_autoconfig: bool = False
    ipv6_dhcp: bool = False
    ipv6_dhcp_setroute: bool = False
    management_only: bool = False
    security_level: Optional[int] = None
    description: Optional[str] = None
    shutdown: bool = False
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    policy_route_maps: List[str] = Field(default_factory=list)


class CiscoNetworkObject(BaseModel):
    name: str
    type: Optional[str] = None
    value: Optional[str] = None
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    nat_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    address_family: Optional[str] = None


class CiscoNetworkGroupMember(BaseModel):
    type: str
    value: str
    address_family: Optional[str] = None
    raw: str = ""
    resolved: Optional[bool] = None
    resolved_target_type: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)

    @property
    def resolved_type(self) -> Optional[str]:
        return self.resolved_target_type

    def __getitem__(self, key: str) -> Any:
        """Keep the old dictionary access working for parser consumers."""
        return getattr(self, key)


class CiscoNetworkGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    address_family: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[CiscoNetworkGroupMember] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoIPv6Address(BaseModel):
    address: str
    standby: Optional[str] = None
    eui64: bool = False
    link_local: bool = False
    raw: str = ""


class CiscoNamedGroupMember(BaseModel):
    type: str
    value: str
    raw: str = ""
    resolved: Optional[bool] = None
    resolved_target_type: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoNamedGroup(BaseModel):
    name: str
    group_type: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[CiscoNamedGroupMember] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoNetworkServiceObject(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoPortSpec(BaseModel):
    operator: str
    values: List[str] = Field(default_factory=list)
    object_name: Optional[str] = None
    raw: str = ""


class CiscoServicePort(BaseModel):
    protocol: str
    destination: Optional[CiscoPortSpec] = None
    source: Optional[CiscoPortSpec] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    raw: str = ""


class CiscoServiceGroupMember(BaseModel):
    type: str
    value: Optional[str] = None
    raw: str = ""
    protocol: Optional[str] = None
    destination: Optional[CiscoPortSpec] = None
    source: Optional[CiscoPortSpec] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    resolved: Optional[bool] = None
    resolved_target_type: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoServiceObject(BaseModel):
    name: str
    ports: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoServiceGroup(BaseModel):
    name: str
    protocol: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    service_objects: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[CiscoServiceGroupMember] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoACLEndpoint(BaseModel):
    type: str
    value: Optional[str] = None
    address_family: Optional[str] = None
    raw: str
    valid: bool = True


class CiscoACLBinding(BaseModel):
    acl_name: str
    interface: Optional[str] = None
    direction: Optional[str] = None
    control_plane: bool = False
    per_user_override: bool = False
    raw_line: str
    line_number: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAccessRule(BaseModel):
    id: str
    acl_name: str
    acl_type: str = "extended"
    source_line_number: Optional[int] = None
    source_order: Optional[int] = None
    source_sequence: Optional[int] = None
    effective_source_order: Optional[int] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    protocol_object: Optional[str] = None
    source_endpoint: Optional[CiscoACLEndpoint] = None
    source_port: Optional[CiscoPortSpec] = None
    destination_endpoint: Optional[CiscoACLEndpoint] = None
    destination_port: Optional[CiscoPortSpec] = None
    service: Optional[str] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    time_range: Optional[str] = None
    log_enabled: Optional[bool] = None
    log_level: Optional[str] = None
    log_interval: Optional[int] = None
    log_raw: Optional[str] = None
    inactive: bool = False
    user: Optional[str] = None
    user_group: Optional[str] = None
    security_group: Optional[str] = None
    source_security_group_type: Optional[str] = None
    source_security_group_value: Optional[str] = None
    destination_security_group_type: Optional[str] = None
    destination_security_group_value: Optional[str] = None
    icmp_object_group: Optional[str] = None
    remark: Optional[str] = None
    raw_line: str = ""
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoNATRule(BaseModel):
    name: str
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    section: str = "manual"
    sequence: Optional[int] = None
    type: str = "source"
    source_mode: Optional[str] = None
    mapped_source_mode: Optional[str] = None
    mapped_source_address_family: Optional[str] = None
    pat_pool: Optional[str] = None
    pat_pool_options: List[str] = Field(default_factory=list)
    real_source: Optional[str] = None
    mapped_source: Optional[str] = None
    destination_mode: Optional[str] = None
    real_destination: Optional[str] = None
    mapped_destination: Optional[str] = None
    original_service: Optional[str] = None
    translated_service: Optional[str] = None
    service_protocol: Optional[str] = None
    owning_object: Optional[str] = None
    access_list: Optional[str] = None
    identity_nat: bool = False
    nat_exemption: bool = False
    object_nat_precedence: Optional[int] = None
    object_nat_specificity: Optional[int] = None
    effective_order_inputs: Dict[str, Any] = Field(default_factory=dict)
    options: List[str] = Field(default_factory=list)
    raw_options: List[str] = Field(default_factory=list)
    net_to_net: bool = False
    dns: bool = False
    no_proxy_arp: bool = False
    route_lookup: bool = False
    unidirectional: bool = False
    inactive: bool = False
    source_sequence: Optional[int] = None
    source_order: Optional[int] = None
    source_order_within_section: Optional[int] = None
    section_order: Optional[int] = None
    effective_source_order: Optional[int] = None
    raw_line: str = ""
    description: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoStaticRoute(BaseModel):
    interface: Optional[str] = None
    destination: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    administrative_distance: Optional[int] = None
    address_family: str = "ipv4"
    routing_context: Optional[str] = None
    track_id: Optional[int] = None
    tunneled: bool = False
    raw_options: List[str] = Field(default_factory=list)
    raw_line: str = ""
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoRouteMapRule(BaseModel):
    name: str
    sequence: int
    action: Optional[str] = None
    match_acl: Optional[str] = None
    set_next_hop: Optional[str] = None
    set_interface: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    raw_options: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoRouteMap(BaseModel):
    name: str
    rules: List[CiscoRouteMapRule] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)


class CiscoTimeRangeClause(BaseModel):
    clause_type: str
    raw: str
    start: Optional[str] = None
    end: Optional[str] = None
    days: List[str] = Field(default_factory=list)
    source_order: int = 0


class CiscoTimeRange(BaseModel):
    name: str
    clauses: List[CiscoTimeRangeClause] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoSourceRecord(BaseModel):
    name: str
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoIKEPolicy(CiscoSourceRecord):
    version: Optional[str] = None
    number: Optional[int] = None
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    integrity: Optional[str] = None
    hash_algorithm: Optional[str] = None
    dh_group: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    prf: Optional[str] = None
    raw_options: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoIKEv2Proposal(CiscoSourceRecord):
    encryption_algorithms: List[str] = Field(default_factory=list)
    integrity_algorithms: List[str] = Field(default_factory=list)
    prf_algorithms: List[str] = Field(default_factory=list)
    dh_groups: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoIPsecTransformSet(CiscoSourceRecord):
    encryption: Optional[str] = None
    authentication: Optional[str] = None
    mode: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoVPNAddressPool(CiscoSourceRecord):
    start: Optional[str] = None
    end: Optional[str] = None
    mask: Optional[str] = None
    address_family: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoCryptoMap(CiscoSourceRecord):
    sequence: Optional[int] = None
    acl_name: Optional[str] = None
    peer: Optional[str] = None
    transform_sets: List[str] = Field(default_factory=list)
    dynamic_map: Optional[str] = None
    map_name: Optional[str] = None
    map_type: Optional[str] = None
    ikev2_proposals: List[str] = Field(default_factory=list)
    pfs_group: Optional[str] = None
    security_association_lifetime_seconds: Optional[int] = None
    security_association_lifetime_kilobytes: Optional[int] = None
    interface_attachment: Optional[str] = None
    is_dynamic: bool = False
    source_order: Optional[int] = None
    raw_options: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoTunnelGroup(CiscoSourceRecord):
    group_type: Optional[str] = None
    default_group_policy: Optional[str] = None
    address_pools: List[str] = Field(default_factory=list)
    authentication_method: Optional[str] = None
    peer_address: Optional[str] = None
    trustpoint: Optional[str] = None
    ikev1_psk_present: bool = False
    ikev2_local_authentication: Optional[str] = None
    ikev2_remote_authentication: Optional[str] = None
    general_attributes: Dict[str, Any] = Field(default_factory=dict)
    ipsec_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoGroupPolicy(CiscoSourceRecord):
    parent: Optional[str] = None
    address_pools: List[str] = Field(default_factory=list)
    dns_servers: List[str] = Field(default_factory=list)
    split_tunnel_policy: Optional[str] = None
    split_tunnel_acl: Optional[str] = None
    vpn_protocols: List[str] = Field(default_factory=list)
    idle_timeout: Optional[str] = None
    session_timeout: Optional[str] = None
    default_domain: Optional[str] = None
    raw_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAARecord(CiscoSourceRecord):
    protocol: Optional[str] = None
    address: Optional[str] = None
    has_secret: Optional[bool] = None


class CiscoAAAServerGroup(CiscoSourceRecord):
    protocol: Optional[str] = None
    hosts: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAServerHost(CiscoSourceRecord):
    group_name: str
    host: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    authentication_port: Optional[int] = None
    accounting_port: Optional[int] = None
    timeout: Optional[int] = None
    retries: Optional[int] = None
    key_present: bool = False
    password_present: bool = False
    server_secret_present: bool = False
    ldap_base_dn: Optional[str] = None
    ldap_scope: Optional[str] = None
    ldap_naming_attribute: Optional[str] = None
    ldap_login_dn: Optional[str] = None
    ldap_over_ssl: Optional[bool] = None
    radius_common_password_present: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoLocalUser(CiscoSourceRecord):
    username: str
    privilege: Optional[int] = None
    authentication_type: Optional[str] = None
    password_present: bool = False
    secret_present: bool = False
    encrypted: bool = False
    nopassword: bool = False
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAAuthenticationRule(CiscoSourceRecord):
    service: Optional[str] = None
    management_protocol: Optional[str] = None
    server_group: Optional[str] = None
    fallback_local: bool = False
    interface: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAAuthorizationRule(CiscoSourceRecord):
    service: Optional[str] = None
    management_protocol: Optional[str] = None
    server_group: Optional[str] = None
    fallback_local: bool = False
    interface: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAAccountingRule(CiscoSourceRecord):
    service: Optional[str] = None
    management_protocol: Optional[str] = None
    server_group: Optional[str] = None
    fallback_local: bool = False
    interface: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoClassMapMatch(BaseModel):
    match_type: str
    value: Optional[str] = None
    acl_name: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None
    class_map_name: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    resolved: Optional[bool] = None
    resolved_target_type: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoClassMap(CiscoSourceRecord):
    match_type: Optional[str] = None
    matches: List[CiscoClassMapMatch] = Field(default_factory=list)
    match_any: Optional[bool] = None
    match_all: Optional[bool] = None
    description: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
    match_lines: List[str] = Field(default_factory=list)


class CiscoInspectAction(BaseModel):
    protocol: str
    policy_name: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    raw: str = ""
    source_order: int = 0
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoMPFConnectionAction(BaseModel):
    max_connections: Optional[int] = None
    max_embryonic: Optional[int] = None
    per_client_max: Optional[int] = None
    per_client_embryonic: Optional[int] = None
    random_sequence_number: Optional[str] = None
    tcp_intercept: Optional[str] = None
    timeout_embryonic: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoMPFPoliceAction(BaseModel):
    rate: Optional[int] = None
    burst: Optional[int] = None
    conform_action: Optional[str] = None
    exceed_action: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoPolicyMapClass(BaseModel):
    class_name: str
    source_order: int = 0
    inspect_actions: List[CiscoInspectAction] = Field(default_factory=list)
    connection_actions: List[CiscoMPFConnectionAction] = Field(default_factory=list)
    police_actions: List[CiscoMPFPoliceAction] = Field(default_factory=list)
    tcp_map: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoPolicyMap(CiscoSourceRecord):
    classes: List[CiscoPolicyMapClass] = Field(default_factory=list)
    description: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
    class_sections: List[str] = Field(default_factory=list)


class CiscoTCPMap(CiscoSourceRecord):
    settings: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoServicePolicy(CiscoSourceRecord):
    attachment: Optional[str] = None
    policy_name: Optional[str] = None
    scope: Optional[str] = None
    global_attachment: bool = False
    interface: Optional[str] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDHCPOption(BaseModel):
    code: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None
    raw: str = ""
    source_order: int = 0


class CiscoDHCPServer(CiscoSourceRecord):
    interface: Optional[str] = None
    pool: Optional[str] = None
    pool_start: Optional[str] = None
    pool_end: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    domain_name: Optional[str] = None
    lease_seconds: Optional[int] = None
    options: List[CiscoDHCPOption] = Field(default_factory=list)
    enabled: Optional[bool] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDHCPRelayServer(BaseModel):
    server: str
    interface: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    resolved_interface: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDHCPRelay(CiscoSourceRecord):
    interface: Optional[str] = None
    server: Optional[str] = None
    servers: List[str] = Field(default_factory=list)
    server_entries: List[CiscoDHCPRelayServer] = Field(default_factory=list)
    enabled_interfaces: List[str] = Field(default_factory=list)
    timeout: Optional[int] = None
    options: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDNSServerGroup(CiscoSourceRecord):
    name_servers: List[str] = Field(default_factory=list)
    domain_name: Optional[str] = None
    interface_lookup: List[str] = Field(default_factory=list)
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDNSSettings(CiscoSourceRecord):
    domain_name: Optional[str] = None
    lookup_interfaces: List[str] = Field(default_factory=list)
    default_server_group: Optional[str] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoConnectionControl(CiscoSourceRecord):
    setting: Optional[str] = None
    values: List[str] = Field(default_factory=list)
    control_type: Optional[str] = None
    max_connections: Optional[int] = None
    max_embryonic: Optional[int] = None
    per_client_max: Optional[int] = None
    per_client_embryonic: Optional[int] = None
    timeout_embryonic: Optional[str] = None
    timeout_half_closed: Optional[str] = None
    timeout_tcp: Optional[str] = None
    timeout_udp: Optional[str] = None
    timeout_icmp: Optional[str] = None
    timeout_xlate: Optional[str] = None
    timeout_pat_xlate: Optional[str] = None
    timeout_sunrpc: Optional[str] = None
    timeout_h225: Optional[str] = None
    timeout_h323: Optional[str] = None
    timeout_sip: Optional[str] = None
    timeout_sip_media: Optional[str] = None
    tcp_map: Optional[str] = None
    rate: Optional[int] = None
    burst: Optional[int] = None
    threat_detection_type: Optional[str] = None
    enabled: Optional[bool] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoManagementSetting(CiscoSourceRecord):
    setting: Optional[str] = None


class CiscoSystemSettings(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    hostname: Optional[str] = None
    domain_name: Optional[str] = None
    timezone_name: Optional[str] = None
    timezone_offset: Optional[int] = None
    dst_name: Optional[str] = None
    management_access_interface: Optional[str] = None
    same_security_inter: Optional[bool] = None
    same_security_intra: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoNTPServer(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    server: Optional[str] = None
    interface: Optional[str] = None
    prefer: bool = False
    key_id: Optional[str] = None
    source_order: int = 0
    raw_line: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoManagementAccessRule(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    protocol: str
    source: Optional[str] = None
    mask_or_prefix: Optional[str] = None
    interface: Optional[str] = None
    port: Optional[int] = None
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoSNMPSetting(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    setting_type: str
    host: Optional[str] = None
    interface: Optional[str] = None
    community_present: bool = False
    version: Optional[str] = None
    username: Optional[str] = None
    trap_types: List[str] = Field(default_factory=list)
    location: Optional[str] = None
    contact: Optional[str] = None
    source_order: int = 0
    raw_line: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoLoggingSetting(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    setting_type: str
    enabled: Optional[bool] = None
    host: Optional[str] = None
    interface: Optional[str] = None
    severity: Optional[str] = None
    facility: Optional[str] = None
    buffer_size: Optional[int] = None
    timestamp: Optional[bool] = None
    source_order: int = 0
    raw_line: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoEnableCredential(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    password_present: bool = False
    secret_present: bool = False
    encrypted: bool = False
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoFailoverSetting(CiscoSourceRecord):
    setting: Optional[str] = None


class CiscoFailoverInterfaceIP(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    logical_name: Optional[str] = None
    interface: Optional[str] = None
    active_ip: Optional[str] = None
    standby_ip: Optional[str] = None
    netmask_or_prefix: Optional[str] = None
    address_family: str = "ipv4"
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoFailoverMACAddress(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    interface: Optional[str] = None
    active_mac: Optional[str] = None
    standby_mac: Optional[str] = None
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoFailoverConfig(CiscoSourceRecord):
    migration_status: str = "PARTIALLY_NORMALIZED"
    enabled: Optional[bool] = None
    unit_role: Optional[str] = None
    lan_interface_name: Optional[str] = None
    lan_interface: Optional[str] = None
    stateful_link_name: Optional[str] = None
    stateful_link_interface: Optional[str] = None
    interface_ips: List[CiscoFailoverInterfaceIP] = Field(default_factory=list)
    mac_addresses: List[CiscoFailoverMACAddress] = Field(default_factory=list)
    replication_http: Optional[bool] = None
    polltime: Optional[str] = None
    holdtime: Optional[str] = None
    timeout: Optional[str] = None
    key_present: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoASAContext(CiscoSourceRecord):
    config_url: Optional[str] = None
    admin_context: Optional[bool] = None
    allocated_interfaces: List[str] = Field(default_factory=list)
    resource_class: Optional[str] = None


class CiscoDiagnostic(BaseModel):
    line_number: int
    section: str
    object_name: Optional[str] = None
    raw_line: str
    severity: str = "error"
    reason: str
    migration_effect: str = "PARSE_ERROR"


class CiscoASAConfig(BaseModel):
    hostname: str = "cisco-asa"
    interfaces: List[CiscoInterface] = Field(default_factory=list)
    network_objects: List[CiscoNetworkObject] = Field(default_factory=list)
    network_groups: List[CiscoNetworkGroup] = Field(default_factory=list)
    protocol_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    icmp_type_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    user_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    security_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    network_service_objects: List[CiscoNetworkServiceObject] = Field(default_factory=list)
    network_service_groups: List[CiscoNetworkServiceObject] = Field(default_factory=list)
    service_objects: List[CiscoServiceObject] = Field(default_factory=list)
    service_groups: List[CiscoServiceGroup] = Field(default_factory=list)
    access_rules: List[CiscoAccessRule] = Field(default_factory=list)
    acl_bindings: List[CiscoACLBinding] = Field(default_factory=list)
    nat_rules: List[CiscoNATRule] = Field(default_factory=list)
    static_routes: List[CiscoStaticRoute] = Field(default_factory=list)
    route_maps: List[CiscoRouteMap] = Field(default_factory=list)
    time_ranges: List[CiscoTimeRange] = Field(default_factory=list)
    ike_policies: List[CiscoIKEPolicy] = Field(default_factory=list)
    ikev2_proposals: List[CiscoIKEv2Proposal] = Field(default_factory=list)
    ipsec_transform_sets: List[CiscoIPsecTransformSet] = Field(default_factory=list)
    vpn_address_pools: List[CiscoVPNAddressPool] = Field(default_factory=list)
    crypto_maps: List[CiscoCryptoMap] = Field(default_factory=list)
    tunnel_groups: List[CiscoTunnelGroup] = Field(default_factory=list)
    group_policies: List[CiscoGroupPolicy] = Field(default_factory=list)
    aaa_records: List[CiscoAAARecord] = Field(default_factory=list)
    aaa_server_groups: List[CiscoAAAServerGroup] = Field(default_factory=list)
    aaa_server_hosts: List[CiscoAAAServerHost] = Field(default_factory=list)
    local_users: List[CiscoLocalUser] = Field(default_factory=list)
    aaa_authentication_rules: List[CiscoAAAAuthenticationRule] = Field(default_factory=list)
    aaa_authorization_rules: List[CiscoAAAAuthorizationRule] = Field(default_factory=list)
    aaa_accounting_rules: List[CiscoAAAAccountingRule] = Field(default_factory=list)
    class_maps: List[CiscoClassMap] = Field(default_factory=list)
    policy_maps: List[CiscoPolicyMap] = Field(default_factory=list)
    service_policies: List[CiscoServicePolicy] = Field(default_factory=list)
    tcp_maps: List[CiscoTCPMap] = Field(default_factory=list)
    dhcp_servers: List[CiscoDHCPServer] = Field(default_factory=list)
    dhcp_relays: List[CiscoDHCPRelay] = Field(default_factory=list)
    dns_server_groups: List[CiscoDNSServerGroup] = Field(default_factory=list)
    dns_settings: CiscoDNSSettings = Field(default_factory=lambda: CiscoDNSSettings(name="system-dns"))
    connection_controls: List[CiscoConnectionControl] = Field(default_factory=list)
    management_settings: List[CiscoManagementSetting] = Field(default_factory=list)
    system_settings: CiscoSystemSettings = Field(default_factory=lambda: CiscoSystemSettings(name="system"))
    ntp_servers: List[CiscoNTPServer] = Field(default_factory=list)
    management_access_rules: List[CiscoManagementAccessRule] = Field(default_factory=list)
    snmp_settings: List[CiscoSNMPSetting] = Field(default_factory=list)
    logging_settings: List[CiscoLoggingSetting] = Field(default_factory=list)
    enable_credentials: List[CiscoEnableCredential] = Field(default_factory=list)
    failover_settings: List[CiscoFailoverSetting] = Field(default_factory=list)
    failover_config: CiscoFailoverConfig = Field(default_factory=lambda: CiscoFailoverConfig(name="failover"))
    contexts: List[CiscoASAContext] = Field(default_factory=list)
    acl_consumers: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    unsupported_commands: List[Dict[str, Any]] = Field(default_factory=list)
    parse_errors: List[Dict[str, Any]] = Field(default_factory=list)
    diagnostics: List[CiscoDiagnostic] = Field(default_factory=list)
    reference_issues: List[Dict[str, Any]] = Field(default_factory=list)
