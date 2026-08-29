"""Junos SRX intermediate source configuration models."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


class JuniperInterfaceAddress(BaseModel):
    family: str = "inet"  # inet or inet6
    address: str
    primary: bool = False
    preferred: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperInterfaceUnit(BaseModel):
    unit: str
    description: Optional[str] = None
    vlan_id: Optional[int] = None
    addresses: List[JuniperInterfaceAddress] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperInterface(BaseModel):
    name: str
    description: Optional[str] = None
    disabled: bool = False
    units: Dict[str, JuniperInterfaceUnit] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperZone(BaseModel):
    name: str
    description: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    screen: Optional[str] = None
    host_inbound_system_services: List[str] = Field(default_factory=list)
    host_inbound_protocols: List[str] = Field(default_factory=list)
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


class JuniperAddressSetMember(BaseModel):
    name: str
    member_type: str = "address"  # address | address-set


class JuniperAddressSet(BaseModel):
    name: str
    address_book: str = "global"
    zone: Optional[str] = None
    members: List[JuniperAddressSetMember] = Field(default_factory=list)
    description: Optional[str] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAddressBook(BaseModel):
    name: str = "global"
    attached_zones: List[str] = Field(default_factory=list)
    addresses: Dict[str, JuniperAddress] = Field(default_factory=dict)
    address_sets: Dict[str, JuniperAddressSet] = Field(default_factory=dict)
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


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
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperApplication(BaseModel):
    name: str
    description: Optional[str] = None
    terms: List[JuniperApplicationTerm] = Field(default_factory=list)
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperApplicationSet(BaseModel):
    name: str
    applications: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    disabled: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


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
    count: bool = False
    description: Optional[str] = None
    disabled: bool = False
    permit_options: Dict[str, Any] = Field(default_factory=dict)
    unknown_match_conditions: Dict[str, Any] = Field(default_factory=dict)
    unknown_then_options: Dict[str, Any] = Field(default_factory=dict)
    sequence: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    parsed_match_fields: List[str] = Field(default_factory=list)


class JuniperScheduler(BaseModel):
    name: str
    description: Optional[str] = None
    start_date: Optional[str] = None
    stop_date: Optional[str] = None
    daily: List[str] = Field(default_factory=list)
    weekdays: Dict[str, str] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


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
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATPool(BaseModel):
    name: str
    nat_type: str = "source"  # source | destination
    addresses: List[str] = Field(default_factory=list)
    ports: List[str] = Field(default_factory=list)
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
    authentication_method: Optional[str] = None
    dh_group: Optional[str] = None
    authentication_algorithm: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIKEPolicy(BaseModel):
    name: str
    mode: Optional[str] = None
    proposal_set: Optional[str] = None
    proposals: List[str] = Field(default_factory=list)
    has_pre_shared_key: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIKEGateway(BaseModel):
    name: str
    ike_policy: Optional[str] = None
    address: Optional[str] = None
    external_interface: Optional[str] = None
    version: Optional[str] = None
    local_address: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecProposal(BaseModel):
    name: str
    protocol: Optional[str] = None  # esp | ah
    authentication_algorithm: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecPolicy(BaseModel):
    name: str
    proposal_set: Optional[str] = None
    proposals: List[str] = Field(default_factory=list)
    pfs_group: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecVPN(BaseModel):
    name: str
    bind_interface: Optional[str] = None
    ike_gateway: Optional[str] = None
    ipsec_policy: Optional[str] = None
    establish_tunnels: Optional[str] = None
    traffic_selectors: List[Dict[str, Any]] = Field(default_factory=list)
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


class JuniperContextConfig(BaseModel):
    name: str = "root"
    context_type: str = "root"  # root, logical-system, tenant
    interfaces: Dict[str, JuniperInterface] = Field(default_factory=dict)
    zones: Dict[str, JuniperZone] = Field(default_factory=dict)
    address_books: Dict[str, JuniperAddressBook] = Field(default_factory=dict)
    applications: Dict[str, JuniperApplication] = Field(default_factory=dict)
    application_sets: Dict[str, JuniperApplicationSet] = Field(default_factory=dict)
    policies: List[JuniperPolicy] = Field(default_factory=list)
    global_policies: List[JuniperPolicy] = Field(default_factory=list)
    schedulers: Dict[str, JuniperScheduler] = Field(default_factory=dict)
    routes: List[JuniperRoute] = Field(default_factory=list)
    nat: JuniperNATConfig = Field(default_factory=JuniperNATConfig)
    vpn: JuniperVPNConfig = Field(default_factory=JuniperVPNConfig)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSRXConfig(BaseModel):
    hostname: Optional[str] = None
    version: Optional[str] = None
    time_zone: Optional[str] = None
    name_servers: List[str] = Field(default_factory=list)
    contexts: Dict[str, JuniperContextConfig] = Field(default_factory=dict)
    unsupported_commands: List[JunosCommand] = Field(default_factory=list)

    def get_context(self, name: str = "root", context_type: str = "root") -> JuniperContextConfig:
        if name not in self.contexts:
            self.contexts[name] = JuniperContextConfig(name=name, context_type=context_type)
        return self.contexts[name]
