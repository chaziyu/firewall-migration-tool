"""Junos SRX intermediate source configuration models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


class JuniperContextType(str, Enum):
    ROOT = "root"
    LOGICAL_SYSTEM = "logical-system"
    TENANT = "tenant"


@dataclass(frozen=True)
class JuniperConfigContext:
    context_type: JuniperContextType
    name: Optional[str] = None

    @property
    def key(self) -> tuple[JuniperContextType, Optional[str]]:
        return self.context_type, self.name


class JuniperProvenanceKind(str, Enum):
    LOCAL = "LOCAL"
    INHERITED_GROUP = "INHERITED_GROUP"
    PREDEFINED_SHARED = "PREDEFINED_SHARED"


@dataclass(frozen=True)
class JuniperSourceProvenance:
    kind: JuniperProvenanceKind = JuniperProvenanceKind.LOCAL
    context: Optional[JuniperConfigContext] = None
    group_name: Optional[str] = None
    source_path: Optional[tuple[str, ...]] = None


@dataclass(frozen=True)
class JuniperEffectiveProvenance:
    provenance_kind: JuniperProvenanceKind = JuniperProvenanceKind.LOCAL
    source_context: Optional[JuniperConfigContext] = None
    source_group_name: Optional[str] = None
    source_group_chain: tuple[str, ...] = ()
    source_path: Optional[tuple[str, ...]] = None
    target_context: Optional[JuniperConfigContext] = None
    target_path: Optional[tuple[str, ...]] = None
    hierarchy_depth: int = 0
    group_priority: int = 0
    recursion_depth: int = 0
    source_order: int = 0
    overridden: bool = False
    excluded: bool = False
    inactive: bool = False


class JuniperGroupStatement(BaseModel):
    hierarchy_path: tuple[str, ...] = ()
    leaf_keyword: str
    leaf_values: List[str] = Field(default_factory=list)
    active: bool = True
    source_order: int = 0
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    referenced_group_name: Optional[str] = None
    source_group_name: Optional[str] = None
    source_path: Optional[tuple[str, ...]] = None


class JuniperGroupNode(BaseModel):
    path_component: str
    wildcard: bool = False
    children: Dict[str, "JuniperGroupNode"] = Field(default_factory=dict)
    statements: List[JuniperGroupStatement] = Field(default_factory=list)
    apply_groups: List[str] = Field(default_factory=list)
    apply_groups_except: List[str] = Field(default_factory=list)
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    apply_group_provenance: List[Dict[str, Any]] = Field(default_factory=list)


class JuniperConfigurationGroup(BaseModel):
    name: str
    root_node: JuniperGroupNode
    source_metadata: Dict[str, Any] = Field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.root_node.children or self.root_node.statements)


class JuniperInterfaceAddress(BaseModel):
    family: str = "inet"  # inet or inet6
    address: str
    primary: bool = False
    preferred: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: Optional[JuniperEffectiveProvenance] = None


class JuniperInterfaceUnit(BaseModel):
    unit: str
    description: Optional[str] = None
    vlan_id: Optional[int] = None
    encapsulation: Optional[str] = None
    family_attributes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    filters: List[Dict[str, Any]] = Field(default_factory=list)
    vrrp: List[Dict[str, Any]] = Field(default_factory=list)
    addresses: List[JuniperInterfaceAddress] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    field_provenance: Dict[str, JuniperEffectiveProvenance] = Field(default_factory=dict)


class JuniperScreenOption(BaseModel):
    path: List[str]
    values: List[str] = Field(default_factory=list)
    disabled: bool = False


class JuniperScreenProfile(BaseModel):
    name: str
    options: List[JuniperScreenOption] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperFirewallFilterTerm(BaseModel):
    name: str
    matches: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    from_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperFirewallFilter(BaseModel):
    name: str
    family: str = "inet"
    terms: List[JuniperFirewallFilterTerm] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperInterface(BaseModel):
    name: str
    interface_type: Optional[str] = None
    description: Optional[str] = None
    disabled: bool = False
    mtu: Optional[int] = None
    speed: Optional[str] = None
    link_mode: Optional[str] = None
    encapsulation: Optional[str] = None
    physical_link: Dict[str, Any] = Field(default_factory=dict)
    aggregate_parent: Optional[str] = None
    aggregate_members: List[str] = Field(default_factory=list)
    aggregate_options: List[Dict[str, Any]] = Field(default_factory=list)
    redundant_parent: Optional[str] = None
    redundancy_group: Optional[str] = None
    units: Dict[str, JuniperInterfaceUnit] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    field_provenance: Dict[str, JuniperEffectiveProvenance] = Field(default_factory=dict)


class JuniperZone(BaseModel):
    name: str
    description: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    screen: Optional[str] = None
    host_inbound_system_services: List[str] = Field(default_factory=list)
    host_inbound_protocols: List[str] = Field(default_factory=list)
    interface_host_inbound: Dict[str, Dict[str, List[str]]] = Field(default_factory=dict)
    disabled_host_inbound: Dict[str, List[str]] = Field(default_factory=dict)
    tcp_rst: bool = False
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAddress(BaseModel):
    name: str
    address_book: str = "global"
    zone: Optional[str] = None
    type: str = "ip-prefix"  # ip-prefix, dns-name, dns-address, range-address, wildcard-address
    prefix: Optional[str] = None
    fqdn: Optional[str] = None
    range_start: Optional[str] = None
    range_end: Optional[str] = None
    wildcard: Optional[str] = None
    description: Optional[str] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperAddressSetMember(BaseModel):
    name: str
    member_type: str = "address"  # address | address-set
    disabled: bool = False
    source_path: Optional[str] = None


class JuniperAddressSet(BaseModel):
    name: str
    address_book: str = "global"
    zone: Optional[str] = None
    members: List[JuniperAddressSetMember] = Field(default_factory=list)
    description: Optional[str] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperAddressBook(BaseModel):
    name: str = "global"
    attached_zones: List[str] = Field(default_factory=list)
    addresses: Dict[str, JuniperAddress] = Field(default_factory=dict)
    address_sets: Dict[str, JuniperAddressSet] = Field(default_factory=dict)
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperApplicationTerm(BaseModel):
    name: Optional[str] = None
    protocol: Optional[str] = None
    protocol_number: Optional[int] = None
    source_ports: List[str] = Field(default_factory=list)
    destination_ports: List[str] = Field(default_factory=list)
    icmp_type: Optional[Union[str, int]] = None
    icmp_code: Optional[Union[str, int]] = None
    application_protocol: Optional[str] = None
    inactivity_timeout: Optional[Union[str, int]] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperApplication(BaseModel):
    name: str
    description: Optional[str] = None
    terms: List[JuniperApplicationTerm] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperApplicationSet(BaseModel):
    name: str
    applications: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperPolicy(BaseModel):
    name: str
    policy_scope: str = "zone"  # zone | global
    from_zones: List[str] = Field(default_factory=list)
    to_zones: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    source_address_excluded: bool = False
    destination_address_excluded: bool = False
    dynamic_applications: List[str] = Field(default_factory=list)
    source_identities: List[str] = Field(default_factory=list)
    source_end_user_profiles: List[str] = Field(default_factory=list)
    scheduler_name: Optional[str] = None
    action: Optional[str] = None  # permit, deny, reject, or None
    log_session_init: bool = False
    log_session_close: bool = False
    logging_options: List[Dict[str, Any]] = Field(default_factory=list)
    count: bool = False
    description: Optional[str] = None
    disabled: bool = False
    permit_options: Dict[str, Any] = Field(default_factory=dict)
    unknown_match_conditions: Dict[str, Any] = Field(default_factory=dict)
    unknown_then_options: Dict[str, Any] = Field(default_factory=dict)
    sequence: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    parsed_match_fields: List[str] = Field(default_factory=list)
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    policy_key: Optional[str] = None
    permit_option_paths: List[List[str]] = Field(default_factory=list)
    vpn_action: Optional[str] = None
    vpn_reference: Optional[str] = None
    application_services: List[str] = Field(default_factory=list)
    security_profile_references: Dict[str, List[str]] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperIDPRule(BaseModel):
    name: str
    match: Dict[str, List[str]] = Field(default_factory=dict)
    exceptions: List[str] = Field(default_factory=list)
    action: Optional[str] = None
    severity: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIDPPolicy(BaseModel):
    name: str
    rulebase: Dict[str, List[JuniperIDPRule]] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSSLProxyProfile(BaseModel):
    name: str
    references: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSecurityIntelligenceFeed(BaseModel):
    name: str
    references: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSecurityIntelligenceProfile(BaseModel):
    name: str
    feeds: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRPMTest(BaseModel):
    owner: str
    name: str
    target: Optional[str] = None
    test_type: Optional[str] = None
    probe_count: Optional[int] = None
    probe_interval: Optional[str] = None
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    traps: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRPMProbe(BaseModel):
    owner: str
    name: str
    tests: Dict[str, JuniperRPMTest] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperChassisItem(BaseModel):
    hierarchy: str
    values: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRPMTest(BaseModel):
    owner: str
    name: str
    target: Optional[str] = None
    test_type: Optional[str] = None
    probe_count: Optional[int] = None
    probe_interval: Optional[str] = None
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    traps: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRPMProbe(BaseModel):
    owner: str
    name: str
    tests: Dict[str, JuniperRPMTest] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperChassisItem(BaseModel):
    hierarchy: str
    values: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperScheduler(BaseModel):
    name: str
    description: Optional[str] = None
    start_date: Optional[str] = None
    stop_date: Optional[str] = None
    daily: List[str] = Field(default_factory=list)
    weekdays: Dict[str, str] = Field(default_factory=dict)
    daily_windows: List[Dict[str, Any]] = Field(default_factory=list)
    weekday_windows: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    exclusions: List[Dict[str, Any]] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperRouteNextHop(BaseModel):
    value: str
    qualified: bool = False
    preference: Optional[int] = None
    metric: Optional[int] = None
    tag: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRoute(BaseModel):
    destination: str
    routing_instance: Optional[str] = None
    next_hops: List[JuniperRouteNextHop] = Field(default_factory=list)
    next_table: Optional[str] = None
    discard: bool = False
    reject: bool = False
    receive: bool = False
    preference: Optional[int] = None
    metric: Optional[int] = None
    tag: Optional[int] = None
    disabled: bool = False
    retain: bool = False
    action: Optional[str] = None
    rib: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATPool(BaseModel):
    name: str
    nat_type: str = "source"  # source | destination
    addresses: List[str] = Field(default_factory=list)
    ports: List[str] = Field(default_factory=list)
    address_ranges: List[Dict[str, str]] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATContext(BaseModel):
    zones: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    routing_instances: List[str] = Field(default_factory=list)


class JuniperNATMatch(BaseModel):
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    source_address_names: List[str] = Field(default_factory=list)
    destination_address_names: List[str] = Field(default_factory=list)
    source_ports: List[str] = Field(default_factory=list)
    destination_ports: List[str] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    unknown_match_conditions: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATRule(BaseModel):
    name: str
    nat_type: str = "source"  # source | destination | static
    nat_family: str = "ipv4"  # ipv4 | ipv6 | nptv6
    match: JuniperNATMatch = Field(default_factory=JuniperNATMatch)
    action: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    disabled: bool = False
    sequence: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATRuleSet(BaseModel):
    name: str
    nat_type: str = "source"  # source | destination | static
    from_context: JuniperNATContext = Field(default_factory=JuniperNATContext)
    to_context: Optional[JuniperNATContext] = None
    rules: List[JuniperNATRule] = Field(default_factory=list)
    description: Optional[str] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATConfig(BaseModel):
    source_pools: Dict[str, JuniperNATPool] = Field(default_factory=dict)
    destination_pools: Dict[str, JuniperNATPool] = Field(default_factory=dict)
    source_rule_sets: Dict[str, JuniperNATRuleSet] = Field(default_factory=dict)
    destination_rule_sets: Dict[str, JuniperNATRuleSet] = Field(default_factory=dict)
    static_rule_sets: Dict[str, JuniperNATRuleSet] = Field(default_factory=dict)
    proxy_arp: List[Dict[str, Any]] = Field(default_factory=list)
    proxy_ndp: List[Dict[str, Any]] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIKEProposal(BaseModel):
    name: str
    description: Optional[str] = None
    authentication_method: Optional[str] = None
    dh_group: Optional[str] = None
    authentication_algorithm: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    digital_signature_scheme: Optional[str] = None
    prf_algorithm: Optional[str] = None
    signature_hash_algorithm: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIKEPolicy(BaseModel):
    name: str
    mode: Optional[str] = None
    proposal_set: Optional[str] = None
    proposals: List[str] = Field(default_factory=list)
    has_pre_shared_key: bool = False
    certificate_reference: Optional[str] = None
    local_certificate: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIKEGateway(BaseModel):
    name: str
    ike_policy: Optional[str] = None
    address: Optional[str] = None
    external_interface: Optional[str] = None
    version: Optional[str] = None
    local_address: Optional[str] = None
    local_identity: Optional[str] = None
    remote_identity: Optional[str] = None
    nat_traversal: Optional[bool] = None
    dpd: Dict[str, Any] = Field(default_factory=dict)
    certificate_reference: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecProposal(BaseModel):
    name: str
    description: Optional[str] = None
    protocol: Optional[str] = None  # esp | ah
    authentication_algorithm: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    lifetime_kilobytes: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecPolicy(BaseModel):
    name: str
    proposal_set: Optional[str] = None
    proposals: List[str] = Field(default_factory=list)
    pfs_group: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperTrafficSelectorTerm(BaseModel):
    name: str
    local_ip: List[str] = Field(default_factory=list)
    remote_ip: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    local_port: List[str] = Field(default_factory=list)
    remote_port: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperTrafficSelector(BaseModel):
    name: str
    local_ip: List[str] = Field(default_factory=list)
    remote_ip: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    local_port: List[str] = Field(default_factory=list)
    remote_port: List[str] = Field(default_factory=list)
    terms: Dict[str, JuniperTrafficSelectorTerm] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperVPNMonitor(BaseModel):
    enabled: bool = True
    destination_ip: Optional[str] = None
    source_interface: Optional[str] = None
    options: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecVPN(BaseModel):
    name: str
    bind_interface: Optional[str] = None
    ike_gateway: Optional[str] = None
    ipsec_policy: Optional[str] = None
    establish_tunnels: Optional[str] = None
    traffic_selectors: Dict[str, JuniperTrafficSelector] = Field(default_factory=dict)
    vpn_monitor: Optional[JuniperVPNMonitor] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperVPNConfig(BaseModel):
    ike_proposals: Dict[str, JuniperIKEProposal] = Field(default_factory=dict)
    ike_policies: Dict[str, JuniperIKEPolicy] = Field(default_factory=dict)
    ike_gateways: Dict[str, JuniperIKEGateway] = Field(default_factory=dict)
    ipsec_proposals: Dict[str, JuniperIPSecProposal] = Field(default_factory=dict)
    ipsec_policies: Dict[str, JuniperIPSecPolicy] = Field(default_factory=dict)
    ipsec_vpns: Dict[str, JuniperIPSecVPN] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSourceHierarchyItem(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    disabled: bool = False


class JuniperUTMAntivirusProfile(BaseModel):
    name: str
    engine_type: Optional[str] = None
    scan_behavior: Dict[str, Any] = Field(default_factory=dict)
    fallback_behavior: Dict[str, Any] = Field(default_factory=dict)
    file_controls: List[str] = Field(default_factory=list)
    mime_types: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperUTMWebFilteringProfile(BaseModel):
    name: str
    url_categories: List[str] = Field(default_factory=list)
    custom_url_lists: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    logging: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperUTMContentFilteringProfile(BaseModel):
    name: str
    syntax_variant: Optional[str] = None
    content_types: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperUTMAntiSpamProfile(BaseModel):
    name: str
    servers: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAppSecureRule(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAppSecureRuleSet(BaseModel):
    name: str
    rules: List[JuniperAppSecureRule] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperPolicer(BaseModel):
    name: str
    bandwidth_limit: Optional[str] = None
    burst_limit: Optional[str] = None
    action: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperPrefixList(BaseModel):
    name: str
    entries: List[str] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperCoSScheduler(BaseModel):
    name: str
    transmit_rate: Optional[str] = None
    shaping_rate: Optional[str] = None
    priority: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperVLAN(BaseModel):
    name: str
    vlan_id: Optional[int] = None
    l3_interface: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRoutingInstance(BaseModel):
    name: str
    instance_type: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    route_distinguisher: Optional[str] = None
    import_policies: List[str] = Field(default_factory=list)
    export_policies: List[str] = Field(default_factory=list)
    routing_options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDNSNameServer(BaseModel):
    server: str
    routing_instance: Optional[str] = None
    source_interface: Optional[str] = None


class JuniperNTPServer(BaseModel):
    address: str
    role: str = "server"
    preferred: bool = False
    routing_instance: Optional[str] = None
    authentication_key_reference: Optional[str] = None


class JuniperNTPSettings(BaseModel):
    servers: List[JuniperNTPServer] = Field(default_factory=list)
    source_address: Optional[str] = None
    source_interface: Optional[str] = None
    routing_instance: Optional[str] = None
    authentication_keys: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperLoginClass(JuniperSourceHierarchyItem):
    pass


class JuniperAdminUser(JuniperSourceHierarchyItem):
    login_class: Optional[str] = None


class JuniperSSHSettings(BaseModel):
    enabled: bool = False
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNETCONFSettings(BaseModel):
    enabled: bool = False
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperWebManagementSettings(BaseModel):
    http_enabled: bool = False
    https_enabled: bool = False
    http_options: Dict[str, Any] = Field(default_factory=dict)
    https_options: Dict[str, Any] = Field(default_factory=dict)
    interfaces: List[str] = Field(default_factory=list)
    certificate_references: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSNMPSettings(BaseModel):
    communities: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    trap_groups: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSyslogSettings(BaseModel):
    destinations: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    files: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    source_address: Optional[str] = None
    source_interface: Optional[str] = None
    routing_instance: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperCertificate(BaseModel):
    name: str
    certificate_id: Optional[str] = None
    ca_profile: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperPKISettings(BaseModel):
    certificates: Dict[str, JuniperCertificate] = Field(default_factory=dict)
    ca_profiles: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    references: Dict[str, List[str]] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSecurityFlowSettings(BaseModel):
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperClusterIPMonitorTarget(BaseModel):
    address: str
    weight: Optional[int] = None
    interface: Optional[str] = None
    secondary_ip_address: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperClusterIPMonitoring(BaseModel):
    global_threshold: Optional[int] = None
    global_weight: Optional[int] = None
    retry_count: Optional[int] = None
    retry_interval: Optional[int] = None
    targets: List[JuniperClusterIPMonitorTarget] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperClusterPreempt(BaseModel):
    enabled: bool = False
    delay: Optional[int] = None
    limit: Optional[int] = None
    period: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRedundancyGroup(BaseModel):
    group_id: str
    nodes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    interface_monitors: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    ip_monitoring: Optional[JuniperClusterIPMonitoring] = None
    preempt: Optional[JuniperClusterPreempt] = None
    hold_down_interval: Optional[int] = None
    gratuitous_arp_count: Optional[int] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperChassisCluster(BaseModel):
    cluster_id: Optional[str] = None
    nodes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    redundancy_groups: Dict[str, JuniperRedundancyGroup] = Field(default_factory=dict)
    fabric_interfaces: List[Dict[str, Any]] = Field(default_factory=list)
    control_links: List[Dict[str, Any]] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPPool(BaseModel):
    name: str
    ranges: List[Dict[str, str]] = Field(default_factory=list)
    router: List[str] = Field(default_factory=list)
    name_servers: List[str] = Field(default_factory=list)
    lease_time: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPRelayGroup(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    server_groups: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperContextConfig(BaseModel):
    name: str = "root"
    context_type: str = "root"  # root, logical-system, tenant
    interfaces: Dict[str, JuniperInterface] = Field(default_factory=dict)
    vlans: Dict[str, "JuniperVLAN"] = Field(default_factory=dict)
    zones: Dict[str, JuniperZone] = Field(default_factory=dict)
    screens: Dict[str, JuniperScreenProfile] = Field(default_factory=dict)
    address_books: Dict[str, JuniperAddressBook] = Field(default_factory=dict)
    applications: Dict[str, JuniperApplication] = Field(default_factory=dict)
    application_sets: Dict[str, JuniperApplicationSet] = Field(default_factory=dict)
    policies: List[JuniperPolicy] = Field(default_factory=list)
    global_policies: List[JuniperPolicy] = Field(default_factory=list)
    schedulers: Dict[str, JuniperScheduler] = Field(default_factory=dict)
    routes: List[JuniperRoute] = Field(default_factory=list)
    routing_instances: Dict[str, JuniperRoutingInstance] = Field(default_factory=dict)
    firewall_filters: Dict[str, JuniperFirewallFilter] = Field(default_factory=dict)
    policers: Dict[str, JuniperPolicer] = Field(default_factory=dict)
    prefix_lists: Dict[str, JuniperPrefixList] = Field(default_factory=dict)
    cos_schedulers: Dict[str, JuniperCoSScheduler] = Field(default_factory=dict)
    dhcp_pools: Dict[str, JuniperDHCPPool] = Field(default_factory=dict)
    dhcp_relays: Dict[str, JuniperDHCPRelayGroup] = Field(default_factory=dict)
    dhcp_local_servers: Dict[str, List[str]] = Field(default_factory=dict)
    nat: JuniperNATConfig = Field(default_factory=JuniperNATConfig)
    vpn: JuniperVPNConfig = Field(default_factory=JuniperVPNConfig)
    access_profiles: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    dynamic_vpns: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    user_identification: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    utm_policies: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    antivirus_profiles: Dict[str, JuniperUTMAntivirusProfile] = Field(default_factory=dict)
    web_filtering_profiles: Dict[str, JuniperUTMWebFilteringProfile] = Field(default_factory=dict)
    content_filtering_profiles: Dict[str, JuniperUTMContentFilteringProfile] = Field(default_factory=dict)
    anti_spam_profiles: Dict[str, JuniperUTMAntiSpamProfile] = Field(default_factory=dict)
    appsecure_rule_sets: Dict[str, JuniperAppSecureRuleSet] = Field(default_factory=dict)
    idp_policies: Dict[str, JuniperIDPPolicy] = Field(default_factory=dict)
    ssl_proxy_profiles: Dict[str, JuniperSSLProxyProfile] = Field(default_factory=dict)
    security_intelligence_feeds: Dict[str, JuniperSecurityIntelligenceFeed] = Field(default_factory=dict)
    security_intelligence_profiles: Dict[str, JuniperSecurityIntelligenceProfile] = Field(default_factory=dict)
    rpm_probes: Dict[str, JuniperRPMProbe] = Field(default_factory=dict)
    chassis: List[JuniperChassisItem] = Field(default_factory=list)
    security_flow: JuniperSecurityFlowSettings = Field(default_factory=JuniperSecurityFlowSettings)
    chassis_cluster: JuniperChassisCluster = Field(default_factory=JuniperChassisCluster)
    management_interfaces: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @property
    def context(self) -> JuniperConfigContext:
        context_type = JuniperContextType(self.context_type)
        return JuniperConfigContext(
            context_type=context_type,
            name=None if context_type is JuniperContextType.ROOT else self.name,
        )


class JuniperSRXConfig(BaseModel):
    hostname: Optional[str] = None
    version: Optional[str] = None
    time_zone: Optional[str] = None
    name_servers: List[JuniperDNSNameServer] = Field(default_factory=list)
    domain_name: Optional[str] = None
    domain_search: List[str] = Field(default_factory=list)
    local_users: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    login_classes: Dict[str, JuniperLoginClass] = Field(default_factory=dict)
    admin_users: Dict[str, JuniperAdminUser] = Field(default_factory=dict)
    radius_servers: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    tacplus_servers: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    authentication_order: List[str] = Field(default_factory=list)
    ntp: JuniperNTPSettings = Field(default_factory=JuniperNTPSettings)
    ssh: JuniperSSHSettings = Field(default_factory=JuniperSSHSettings)
    netconf: JuniperNETCONFSettings = Field(default_factory=JuniperNETCONFSettings)
    web_management: JuniperWebManagementSettings = Field(default_factory=JuniperWebManagementSettings)
    snmp: JuniperSNMPSettings = Field(default_factory=JuniperSNMPSettings)
    syslog: JuniperSyslogSettings = Field(default_factory=JuniperSyslogSettings)
    pki: JuniperPKISettings = Field(default_factory=JuniperPKISettings)
    services: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    contexts: Dict[str, JuniperContextConfig] = Field(default_factory=dict)
    unsupported_commands: List[JunosCommand] = Field(default_factory=list)
    configuration_groups: Dict[str, JuniperConfigurationGroup] = Field(default_factory=dict)
    applied_groups: Dict[str, List[str]] = Field(default_factory=dict)
    applied_group_exceptions: Dict[str, List[str]] = Field(default_factory=dict)

    def get_context(self, name: str = "root", context_type: str = "root") -> JuniperContextConfig:
        if name not in self.contexts:
            self.contexts[name] = JuniperContextConfig(name=name, context_type=context_type)
        return self.contexts[name]
