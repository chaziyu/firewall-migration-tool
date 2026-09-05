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


class CiscoNetworkGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    address_family: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[Dict[str, str]] = Field(default_factory=list)


class CiscoIPv6Address(BaseModel):
    address: str
    standby: Optional[str] = None
    eui64: bool = False
    link_local: bool = False
    raw: str = ""


class CiscoNamedGroup(BaseModel):
    name: str
    group_type: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


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


class CiscoCryptoMap(CiscoSourceRecord):
    sequence: Optional[int] = None
    acl_name: Optional[str] = None
    peer: Optional[str] = None
    transform_sets: List[str] = Field(default_factory=list)
    dynamic_map: Optional[str] = None


class CiscoTunnelGroup(CiscoSourceRecord):
    group_type: Optional[str] = None
    ipsec_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoGroupPolicy(CiscoSourceRecord):
    parent: Optional[str] = None


class CiscoAAARecord(CiscoSourceRecord):
    protocol: Optional[str] = None
    address: Optional[str] = None
    has_secret: Optional[bool] = None


class CiscoClassMap(CiscoSourceRecord):
    match_lines: List[str] = Field(default_factory=list)


class CiscoPolicyMap(CiscoSourceRecord):
    class_sections: List[str] = Field(default_factory=list)


class CiscoServicePolicy(CiscoSourceRecord):
    attachment: Optional[str] = None
    interface: Optional[str] = None


class CiscoDHCPServer(CiscoSourceRecord):
    interface: Optional[str] = None
    pool: Optional[str] = None
    enabled: Optional[bool] = None


class CiscoDHCPRelay(CiscoSourceRecord):
    interface: Optional[str] = None
    server: Optional[str] = None
    enabled: Optional[bool] = None


class CiscoDNSServerGroup(CiscoSourceRecord):
    name_servers: List[str] = Field(default_factory=list)


class CiscoConnectionControl(CiscoSourceRecord):
    setting: Optional[str] = None
    values: List[str] = Field(default_factory=list)


class CiscoManagementSetting(CiscoSourceRecord):
    setting: Optional[str] = None


class CiscoFailoverSetting(CiscoSourceRecord):
    setting: Optional[str] = None


class CiscoASAContext(CiscoSourceRecord):
    config_url: Optional[str] = None
    admin_context: Optional[bool] = None
    allocated_interfaces: List[str] = Field(default_factory=list)


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
    crypto_maps: List[CiscoCryptoMap] = Field(default_factory=list)
    tunnel_groups: List[CiscoTunnelGroup] = Field(default_factory=list)
    group_policies: List[CiscoGroupPolicy] = Field(default_factory=list)
    aaa_records: List[CiscoAAARecord] = Field(default_factory=list)
    class_maps: List[CiscoClassMap] = Field(default_factory=list)
    policy_maps: List[CiscoPolicyMap] = Field(default_factory=list)
    service_policies: List[CiscoServicePolicy] = Field(default_factory=list)
    dhcp_servers: List[CiscoDHCPServer] = Field(default_factory=list)
    dhcp_relays: List[CiscoDHCPRelay] = Field(default_factory=list)
    dns_server_groups: List[CiscoDNSServerGroup] = Field(default_factory=list)
    connection_controls: List[CiscoConnectionControl] = Field(default_factory=list)
    management_settings: List[CiscoManagementSetting] = Field(default_factory=list)
    failover_settings: List[CiscoFailoverSetting] = Field(default_factory=list)
    contexts: List[CiscoASAContext] = Field(default_factory=list)
    acl_consumers: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    unsupported_commands: List[Dict[str, Any]] = Field(default_factory=list)
    parse_errors: List[Dict[str, Any]] = Field(default_factory=list)
    diagnostics: List[CiscoDiagnostic] = Field(default_factory=list)
