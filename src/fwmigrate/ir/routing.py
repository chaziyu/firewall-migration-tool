# Canonical IR routing domain models

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from fwmigrate.ir.enums import IRRouteNextHopType
from .policy import IRFortiGateSourceRule


class IRRoutePathMonitorDestination(BaseModel):
    name: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    destination_reference: Optional[str] = None
    destination_resolved: Optional[bool] = None
    resolved_destination: Optional[str] = None
    source_interface: Optional[str] = None
    source_interface_resolved: Optional[bool] = None
    resolved_source_interface: Optional[str] = None
    interval: Optional[int] = None
    count: Optional[int] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRRoutePathMonitor(BaseModel):
    enabled: Optional[bool] = None
    failure_condition: Optional[str] = None
    hold_time: Optional[str] = None
    recovery_time: Optional[str] = None
    preemptive: Optional[bool] = None
    destinations: List[IRRoutePathMonitorDestination] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRRoute(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    destination: Optional[str] = None
    source_destination: Optional[str] = None
    source_destination_reference: Optional[str] = None
    source_prefix: Optional[str] = None
    source_preferred_source: Optional[str] = None
    source_route_id: Optional[int] = None
    interface: Optional[str] = None
    next_hop: Optional[str] = None
    next_hops: List[str] = Field(default_factory=list)
    next_hop_type: Optional[IRRouteNextHopType] = None
    route_type: Optional[str] = None
    rank: Optional[int] = None
    scope_local: Optional[bool] = None
    monitoring: List[Dict[str, Any]] = Field(default_factory=list)
    administrative_distance: Optional[int] = None
    metric: Optional[int] = None
    priority: Optional[int] = None
    weight: Optional[int] = None
    blackhole: Optional[bool] = None
    enabled: Optional[bool] = None
    installation: Optional[str] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    sdwan_zone: Optional[str] = None
    sdwan_zones: List[str] = Field(default_factory=list)
    dynamic_gateway: Optional[str] = None
    link_monitor_exempt: Optional[str] = None
    bfd: Optional[str] = None
    path_monitor: Optional[IRRoutePathMonitor] = None
    vrf: Optional[int] = None
    route_tag: Optional[int] = None
    internet_service: Optional[int] = None
    internet_service_custom: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    parse_error: Optional[str] = None
    requires_manual_review: bool = False
    source_fabric_object: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @property
    def safe_for_target_generation(self) -> bool:
        return (
            self.migration_status == "NORMALIZED"
            and not self.requires_manual_review
            and not self.review_reasons
            and self.parse_error is None
            and self.destination is not None
            and self.source_destination_reference is None
        )
class IRPBFSymmetricReturn(BaseModel):
    enabled: Optional[bool] = None
    next_hop_addresses: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPolicyBasedForwardingRule(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_rule_id: Optional[str] = None
    source_order: int = 0
    rulebase_position: str = "local"
    from_zone: List[str] = Field(default_factory=list)
    from_interface: List[str] = Field(default_factory=list)
    to: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    source_user: List[str] = Field(default_factory=list)
    application: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    schedule: Optional[str] = None
    source_negated: Optional[bool] = None
    destination_negated: Optional[bool] = None
    action: Optional[str] = None
    forward_to_vsys: Optional[str] = None
    egress_interface: Optional[str] = None
    next_hop_type: Optional[IRRouteNextHopType] = None
    next_hop: Optional[str] = None
    next_vr: Optional[str] = None
    monitor_profile: Optional[str] = None
    monitor_ip: Optional[str] = None
    monitor_enabled: Optional[bool] = None
    disable_if_unreachable: Optional[bool] = None
    enforce_symmetric_return: Optional[bool] = None
    symmetric_return: Optional[IRPBFSymmetricReturn] = None
    enabled: bool = True
    description: Optional[str] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    priority: Optional[int] = None
    protocol: Optional[str] = None
    destination_port: Optional[str] = None
    routing_table: Optional[str] = None
    table_next_hop: Optional[str] = None
    table_output_interface: Optional[str] = None
class IRPolicyRoute(BaseModel):
    """Vendor-neutral policy-based routing intent, separate from static routes."""

    name: str
    source_context: Optional[str] = None
    source_rule_id: Optional[str] = None
    source_order: int = 0
    action: Optional[str] = None
    match_acl: Optional[str] = None
    match_acls: List[str] = Field(default_factory=list)
    resolved_match_criteria: List[str] = Field(default_factory=list)
    match_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    ingress_interface: Optional[str] = None
    next_hop: Optional[str] = None
    next_hops: List[str] = Field(default_factory=list)
    next_interface: Optional[str] = None
    output_interface: Optional[str] = None
    output_interfaces: List[str] = Field(default_factory=list)
    enabled: bool = True
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFortiGatePolicyRoute(IRFortiGateSourceRule):
    """Typed FortiGate PBR semantics retained outside portable route intent."""

    address_family: str = "ipv4"

    source_action: Optional[str] = None
    source_status: Optional[str] = None
    comments: Optional[str] = None

    input_devices: List[str] = Field(default_factory=list)
    input_device_negate: Optional[str] = None

    source_networks: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    source_negate: Optional[str] = None

    destination_networks: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    destination_negate: Optional[str] = None

    protocol: Optional[int] = None
    effective_protocol: Optional[int] = None

    destination_port_start: Optional[int] = None
    destination_port_end: Optional[int] = None
    source_port_start: Optional[int] = None
    source_port_end: Optional[int] = None
    effective_destination_port_start: Optional[int] = None
    effective_destination_port_end: Optional[int] = None
    effective_source_port_start: Optional[int] = None
    effective_source_port_end: Optional[int] = None

    source_explicit_fields: List[str] = Field(default_factory=list)

    gateway: Optional[str] = None
    output_device: Optional[str] = None

    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_ids: List[int] = Field(default_factory=list)

    tos: Optional[str] = None
    tos_mask: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _infer_legacy_address_family(cls, value):
        if isinstance(value, dict) and "address_family" not in value:
            value = dict(value)
            value["address_family"] = (
                "ipv6" if value.get("family") == "policy-route-ipv6" else "ipv4"
            )
        return value
class IRManagementServiceRoute(BaseModel):
    name: Optional[str] = None
    source_context: Optional[str] = None
    source_address: Optional[str] = None
    source_interface: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSDWANZone(BaseModel):
    name: str
    source_context: str = "root"
    source_advpn_health_check: Optional[str] = None
    source_advpn_select: Optional[str] = None
    source_minimum_sla_meet_members: Optional[int] = None
    source_service_sla_tie_break: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSDWANMember(BaseModel):
    source_id: int
    source_context: str = "root"
    interface: str
    zone: str
    gateway: Optional[str] = None
    source: Optional[str] = None
    gateway6: Optional[str] = None
    source6: Optional[str] = None
    preferred_source: Optional[str] = None
    transport_group: Optional[int] = None
    cost: Optional[int] = None
    weight: Optional[int] = None
    priority: Optional[int] = None
    priority6: Optional[int] = None
    spillover_threshold: Optional[int] = None
    ingress_spillover_threshold: Optional[int] = None
    volume_ratio: Optional[int] = None
    status: Optional[str] = None
    description: Optional[str] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
class IRSDWANSLA(BaseModel):
    source_id: int
    source_context: str = "root"
    jitter_threshold: Optional[int] = None
    latency_threshold: Optional[int] = None
    link_cost_factors: List[str] = Field(default_factory=list)
    mos_threshold: Optional[str] = None
    packetloss_threshold: Optional[int] = None
    priority_in_sla: Optional[int] = None
    priority_out_sla: Optional[int] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
class IRSDWANHealthCheck(BaseModel):
    name: str
    source_context: str = "root"
    server: Optional[str] = None
    servers: List[str] = Field(default_factory=list)
    member_ids: List[int] = Field(default_factory=list)
    protocol: Optional[str] = None
    port: Optional[int] = None
    interval: Optional[int] = None
    probe_timeout: Optional[int] = None
    failtime: Optional[int] = None
    recoverytime: Optional[int] = None
    update_static_route: Optional[str] = None
    vrf: Optional[int] = None
    source: Optional[str] = None
    address_mode: Optional[str] = None
    class_id: Optional[int] = None
    detect_mode: Optional[str] = None
    diffserv_code: Optional[str] = None
    dns_match_ip: Optional[str] = None
    dns_request_domain: Optional[str] = None
    embed_measured_health: Optional[str] = None
    ftp_file: Optional[str] = None
    ftp_mode: Optional[str] = None
    ha_priority: Optional[int] = None
    http_agent: Optional[str] = None
    http_get: Optional[str] = None
    http_match: Optional[str] = None
    mos_codec: Optional[str] = None
    packet_size: Optional[int] = None
    has_password: bool = False
    password_format: Optional[str] = None
    probe_count: Optional[int] = None
    probe_packets: Optional[str] = None
    quality_measured_method: Optional[str] = None
    security_mode: Optional[str] = None
    sla_fail_log_period: Optional[int] = None
    sla_id_redistribute: Optional[int] = None
    sla_pass_log_period: Optional[int] = None
    source6: Optional[str] = None
    system_dns: Optional[str] = None
    threshold_alert_jitter: Optional[int] = None
    threshold_alert_latency: Optional[int] = None
    threshold_alert_packetloss: Optional[int] = None
    threshold_warning_jitter: Optional[int] = None
    threshold_warning_latency: Optional[int] = None
    threshold_warning_packetloss: Optional[int] = None
    update_cascade_interface: Optional[str] = None
    user: Optional[str] = None
    sla: List[IRSDWANSLA] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
class IRSDWANRuleSLA(BaseModel):
    name: str
    source_context: str = "root"
    source_id: Optional[int] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSDWANRule(BaseModel):
    source_id: int
    source_context: str = "root"
    name: Optional[str] = None
    mode: Optional[str] = None
    strategy: Optional[str] = None
    status: Optional[str] = None
    address_mode: Optional[str] = None
    agent_exclusive: Optional[str] = None
    bandwidth_weight: Optional[int] = None
    default_service: Optional[str] = None
    dscp_forward: Optional[str] = None
    dscp_forward_tag: Optional[str] = None
    dscp_reverse: Optional[str] = None
    dscp_reverse_tag: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    source_addresses6: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    destination_addresses6: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    destination_negate: Optional[str] = None
    destination_port_start: Optional[int] = None
    destination_port_end: Optional[int] = None
    source_port_start: Optional[int] = None
    source_port_end: Optional[int] = None
    gateway: Optional[str] = None
    user_groups: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hash_mode: Optional[str] = None
    hold_down_time: Optional[int] = None
    input_devices: List[str] = Field(default_factory=list)
    input_device_negate: Optional[str] = None
    input_zones: List[str] = Field(default_factory=list)
    health_check: Optional[str] = None
    health_checks: List[str] = Field(default_factory=list)
    priority_member_ids: List[int] = Field(default_factory=list)
    priority_zones: List[str] = Field(default_factory=list)
    internet_service: Optional[str] = None
    internet_service_names: List[str] = Field(default_factory=list)
    internet_service_app_ctrl: List[int] = Field(default_factory=list)
    internet_service_app_ctrl_categories: List[int] = Field(default_factory=list)
    internet_service_app_ctrl_groups: List[str] = Field(default_factory=list)
    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_custom_groups: List[str] = Field(default_factory=list)
    internet_service_groups: List[str] = Field(default_factory=list)
    jitter_weight: Optional[int] = None
    latency_weight: Optional[int] = None
    packet_loss_weight: Optional[int] = None
    link_cost_factor: Optional[str] = None
    link_cost_threshold: Optional[int] = None
    load_balance: Optional[str] = None
    minimum_sla_meet_members: Optional[int] = None
    passive_measurement: Optional[str] = None
    protocol: Optional[int] = None
    quality_link: Optional[int] = None
    role: Optional[str] = None
    shortcut: Optional[str] = None
    shortcut_priority: Optional[str] = None
    sla_compare_method: Optional[str] = None
    tie_break: Optional[str] = None
    use_shortcut_sla: Optional[str] = None
    sla_stickiness: Optional[str] = None
    source_negate: Optional[str] = None
    standalone_action: Optional[str] = None
    tos: Optional[str] = None
    tos_mask: Optional[str] = None
    zone_mode: Optional[str] = None
    sla: List[IRSDWANRuleSLA] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
class IRSDWANDuplicationRule(BaseModel):
    source_id: int
    source_context: str = "root"
    service_id: Optional[int] = None
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    source_addresses6: List[str] = Field(default_factory=list)
    destination_addresses6: List[str] = Field(default_factory=list)
    source_interfaces: List[str] = Field(default_factory=list)
    destination_interfaces: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    packet_duplication: Optional[str] = None
    sla_match_service: Optional[str] = None
    packet_de_duplication: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSDWANNeighbor(BaseModel):
    name: str
    source_context: str = "root"
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSDWAN(BaseModel):
    source_context: str = "root"
    status: str = "disable"
    load_balance_mode: Optional[str] = None
    zones: List[IRSDWANZone] = Field(default_factory=list)
    members: List[IRSDWANMember] = Field(default_factory=list)
    health_checks: List[IRSDWANHealthCheck] = Field(default_factory=list)
    rules: List[IRSDWANRule] = Field(default_factory=list)
    duplication_rules: List[IRSDWANDuplicationRule] = Field(default_factory=list)
    neighbors: List[IRSDWANNeighbor] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "IRRoutePathMonitorDestination",
    "IRRoutePathMonitor",
    "IRRoute",
    "IRPBFSymmetricReturn",
    "IRPolicyBasedForwardingRule",
    "IRPolicyRoute",
    "IRFortiGatePolicyRoute",
    "IRManagementServiceRoute",
    "IRSDWANZone",
    "IRSDWANMember",
    "IRSDWANSLA",
    "IRSDWANHealthCheck",
    "IRSDWANRuleSLA",
    "IRSDWANRule",
    "IRSDWANDuplicationRule",
    "IRSDWANNeighbor",
    "IRSDWAN",
]
