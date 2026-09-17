# Canonical IR policy domain models

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from fwmigrate.ir.enums import PolicyAction
from .extension_models import (
    IRCheckPointPolicyCompatibilityMixin,
    IRCheckPointPolicyExtension,
    IRFortiOSPolicyCompatibilityMixin,
    IRFortiOSPolicyExtension,
    move_object_extension,
)
from .provenance import IRSourceConfigCommand


class IRSecurityProfileGroup(BaseModel):
    name: str
    source_context: Optional[str] = None

    # Ordered canonical profile memberships.  PAN-OS permits multiple members
    # per family; target generators decide whether that cardinality is portable.
    antivirus_profiles: List[str] = Field(default_factory=list)
    vulnerability_profiles: List[str] = Field(default_factory=list)
    antispyware_profiles: List[str] = Field(default_factory=list)
    url_filtering_profiles: List[str] = Field(default_factory=list)
    file_blocking_profiles: List[str] = Field(default_factory=list)
    wildfire_analysis_profiles: List[str] = Field(default_factory=list)
    data_filtering_profiles: List[str] = Field(default_factory=list)

    # Backward-compatible scalar projections.  They are authoritative only
    # when the corresponding ordered collection contains exactly one member.
    antivirus: Optional[str] = None
    vulnerability: Optional[str] = None
    anti_spyware: Optional[str] = None
    url_filtering: Optional[str] = None
    file_blocking: Optional[str] = None
    wildfire: Optional[str] = None
    data_filtering: Optional[str] = None
    ssl_decryption: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_profile_references: Dict[str, str] = Field(default_factory=dict)
    support_level: str = "TYPED_EXTRACT_ONLY"
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_profile_membership_compatibility(self):
        pairs = (
            ("antivirus", "antivirus_profiles"),
            ("vulnerability", "vulnerability_profiles"),
            ("anti_spyware", "antispyware_profiles"),
            ("url_filtering", "url_filtering_profiles"),
            ("file_blocking", "file_blocking_profiles"),
            ("wildfire", "wildfire_analysis_profiles"),
            ("data_filtering", "data_filtering_profiles"),
        )
        for scalar_field, list_field in pairs:
            values = list(getattr(self, list_field) or [])
            scalar = getattr(self, scalar_field)
            if values:
                setattr(self, scalar_field, values[0] if len(values) == 1 else None)
            elif scalar:
                setattr(self, list_field, [scalar])
        return self
class IRHTTPSInspectionRule(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    rule_number: Optional[int] = None
    source_context: Optional[str] = None
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    action: Optional[str] = None
    certificate: Optional[str] = None
    bypass: Optional[bool] = None
    comments: Optional[str] = None
    enabled: Optional[bool] = None
    install_on: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRIdentitySource(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_type: str
    servers: List[str] = Field(default_factory=list)
    port: Optional[int] = None
    tls: Optional[bool] = None
    certificate: Optional[str] = None
    credentials_present: bool = False
    base_dn: Optional[str] = None
    user_lookup: Dict[str, Any] = Field(default_factory=dict)
    group_lookup: Dict[str, Any] = Field(default_factory=dict)
    enabled: Optional[bool] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAccessRole(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    source_context: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    user_groups: List[str] = Field(default_factory=list)
    machines: List[str] = Field(default_factory=list)
    networks: List[str] = Field(default_factory=list)
    remote_access_roles: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointAccessRule(BaseModel):
    """Complete Check Point access-rule evidence, including non-portable fields."""

    name: str
    source_uuid: Optional[str] = None
    rule_number: Optional[int] = None
    source_context: Optional[str] = None
    domain: Optional[str] = None
    package: Optional[str] = None
    layer: Optional[str] = None
    section_path: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    vpn: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    access_roles: List[str] = Field(default_factory=list)
    action: Optional[str] = None
    track: Any = None
    time: List[str] = Field(default_factory=list)
    install_on: List[str] = Field(default_factory=list)
    source_negated: Optional[bool] = None
    destination_negated: Optional[bool] = None
    service_negated: Optional[bool] = None
    content: List[str] = Field(default_factory=list)
    content_negated: Optional[bool] = None
    inline_layer_reference: Optional[str] = None
    parent_layer: Optional[str] = None
    parent_rule_uid: Optional[str] = None
    comments: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointThreatPreventionRule(BaseModel):
    name: Optional[str] = None
    source_uuid: Optional[str] = None
    rule_number: Optional[int] = None
    source_context: Optional[str] = None
    source_scope: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    profile: Optional[str] = None
    action: Optional[str] = None
    track: Any = None
    install_on: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    enabled: Optional[bool] = None
    exceptions: List[Any] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointThreatPreventionProfile(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    source_context: Optional[str] = None
    family: str
    activation: Dict[str, Any] = Field(default_factory=dict)
    actions: Dict[str, Any] = Field(default_factory=dict)
    confidence_severity_filters: Dict[str, Any] = Field(default_factory=dict)
    exceptions: List[Any] = Field(default_factory=list)
    update_options: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCustomURLCategory(BaseModel):
    name: str
    source_context: Optional[str] = None
    category_type: Optional[str] = None
    entries: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    support_level: str = "TYPED_EXTRACT_ONLY"
    migration_status: str = "EXTRACT_ONLY"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRIPSSensorExemptIP(BaseModel):
    id: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
class IRIPSSensorEntry(BaseModel):
    source_id: int
    source_signature_ids: List[int] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    location: Optional[str] = None
    protocols: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    action: Optional[str] = None
    rate_count: Optional[int] = None
    rate_duration: Optional[int] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    application: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    default_action: Optional[str] = None
    default_status: Optional[str] = None
    log: Optional[str] = None
    log_packet: Optional[str] = None
    log_attack_context: Optional[str] = None
    os: List[str] = Field(default_factory=list)
    rate_mode: Optional[str] = None
    rate_track: Optional[str] = None
    vuln_type: List[int] = Field(default_factory=list)
    quarantine_log: Optional[str] = None
    exempt_ips: List[IRIPSSensorExemptIP] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRIPSSensor(BaseModel):
    name: str
    source_context: Optional[str] = None
    description: Optional[str] = None
    block_malicious_url: Optional[bool] = None
    scan_botnet_connections: Optional[str] = None
    extended_log: Optional[str] = None
    replacemsg_group: Optional[str] = None
    entries: List[IRIPSSensorEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointPolicyPackage(BaseModel):
    uid: Optional[str] = None
    name: str
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    access_layer_uids: List[str] = Field(default_factory=list)
    access_layer_names: List[str] = Field(default_factory=list)
    nat_policy_uid: Optional[str] = None
    nat_policy_name: Optional[str] = None
    threat_prevention_policy_uid: Optional[str] = None
    threat_prevention_policy_name: Optional[str] = None
    installation_targets: List[str] = Field(default_factory=list)
    global_assignment: Optional[str] = None
    source_context: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointAccessLayer(BaseModel):
    uid: Optional[str] = None
    name: str
    package_uid: Optional[str] = None
    package_name: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    parent_layer_uid: Optional[str] = None
    parent_layer_name: Optional[str] = None
    parent_rule_uid: Optional[str] = None
    parent_rule_number: Optional[int] = None
    inline: bool = False
    rule_uids: List[str] = Field(default_factory=list)
    installation_targets: List[str] = Field(default_factory=list)
    source_context: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointDomain(BaseModel):
    uid: Optional[str] = None
    name: str
    domain_type: Optional[str] = None
    management_server: Optional[str] = None
    context: Optional[str] = None
    global_domain_uid: Optional[str] = None
    global_domain_name: Optional[str] = None
    global_assignments: List[str] = Field(default_factory=list)
    source_context: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    policy_package_uids: List[str] = Field(default_factory=list)
    policy_package_names: List[str] = Field(default_factory=list)
    global_object: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointGlobalAssignment(BaseModel):
    uid: Optional[str] = None
    global_domain_uid: Optional[str] = None
    global_domain_name: Optional[str] = None
    target_domain_uid: Optional[str] = None
    target_domain_name: Optional[str] = None
    global_package_uid: Optional[str] = None
    global_package_name: Optional[str] = None
    local_package_uid: Optional[str] = None
    local_package_name: Optional[str] = None
    state: Optional[str] = None
    mode: Optional[str] = None
    assigned_objects: List[str] = Field(default_factory=list)
    assigned_policies: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRMulticastPolicy(BaseModel):
    """Canonical multicast forwarding/filtering intent, independent of NAT."""

    source_id: Optional[int] = None
    source_order: int = 0
    source_context: Optional[str] = None
    source_uuid: Optional[str] = None
    name: Optional[str] = None
    address_family: str = "ipv4"
    enabled: Optional[bool] = True
    action: Optional[str] = "accept"
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    protocol_number: Optional[int] = None
    destination_port_start: Optional[int] = None
    destination_port_end: Optional[int] = None
    utm_status: Optional[str] = None
    ips_sensor: Optional[str] = None
    logtraffic: Optional[str] = None
    traffic_shaper: Optional[str] = None
    auto_asic_offload: Optional[str] = None
    source_snat: Optional[str] = None
    source_snat_ip: Optional[str] = None
    source_dnat: Optional[str] = None
    comments: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
class IRSecurityPolicy(IRCheckPointPolicyCompatibilityMixin, IRFortiOSPolicyCompatibilityMixin, BaseModel):
    # Portable policy intent.  Target generators may consume these fields
    # only when the source-policy audit below confirms semantic safety.
    name: str
    source_context: Optional[str] = None
    vendor_extension: Optional[IRCheckPointPolicyExtension | IRFortiOSPolicyExtension] = None
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    source_ports: List[str] = Field(default_factory=list)
    source_port_reference_statuses: Dict[str, str] = Field(default_factory=dict)
    vlan_criteria: List[str] = Field(default_factory=list)
    variable_sets: List[str] = Field(default_factory=list)
    action: Optional[PolicyAction] = None
    # Source-policy preservation and audit fields.  These retain source
    # syntax/semantics that are not assumed to be portable merely because a
    # corresponding typed field exists in a source parser model.
    source_rule_id: Optional[str] = None
    source_uuid: Optional[str] = None
    source_from_interfaces: List[str] = Field(default_factory=list)
    source_to_interfaces: List[str] = Field(default_factory=list)
    source_address_references: List[str] = Field(default_factory=list)
    destination_address_references: List[str] = Field(default_factory=list)
    source_ipv6_address_references: List[str] = Field(default_factory=list)
    destination_ipv6_address_references: List[str] = Field(default_factory=list)
    source_address_negate_setting: Optional[str] = None
    destination_address_negate_setting: Optional[str] = None
    source_ipv6_address_negate_setting: Optional[str] = None
    destination_ipv6_address_negate_setting: Optional[str] = None
    source_service_references: List[str] = Field(default_factory=list)
    source_service_negate_setting: Optional[str] = None
    source_action: Optional[str] = None
    source_schedule: Optional[str] = None
    source_user_groups: List[str] = Field(default_factory=list)
    source_users: List[str] = Field(default_factory=list)
    unresolved_user_groups: List[str] = Field(default_factory=list)
    unresolved_users: List[str] = Field(default_factory=list)
    identity_dependency_review: bool = False
    source_log_setting: Optional[str] = None
    source_log_setting_resolved: Optional[bool] = None
    resolved_source_log_setting: Optional[str] = None
    source_log_start_setting: Optional[str] = None
    source_extra_setting_commands: List[IRSourceConfigCommand] = Field(default_factory=list)
    source_profile_type: Optional[str] = None
    source_profile_group: Optional[str] = None
    source_profile_protocol_options: Optional[str] = None
    unresolved_security_profiles: List[str] = Field(default_factory=list)
    source_security_profile_references: Dict[str, str] = Field(default_factory=dict)
    security_profile_reference_statuses: Dict[str, str] = Field(default_factory=dict)
    unresolved_security_profile_references: Dict[str, str] = Field(default_factory=dict)
    security_profile_semantics_review: bool = False
    source_extra_settings: Dict[str, Any] = Field(default_factory=dict)
    nat_enabled: Optional[bool] = None
    nat_pool_enabled: Optional[bool] = None
    nat_pool_names: List[str] = Field(default_factory=list)
    nat_pool_names6: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    description: Optional[str] = None
    schedule: Optional[str] = None
    schedules: List[str] = Field(default_factory=list)
    log_start: Optional[bool] = None
    log_end: Optional[bool] = None
    disabled: Optional[bool] = None
    # Canonical policy match/profile semantics.  Ordered collections retain
    # source cardinality; legacy scalar fields below are compatibility views.
    url_categories: List[str] = Field(default_factory=list)
    url_category_reference_statuses: Dict[str, str] = Field(default_factory=dict)
    unresolved_url_categories: List[str] = Field(default_factory=list)
    security_profile_groups: List[str] = Field(default_factory=list)
    antivirus_profiles: List[str] = Field(default_factory=list)
    vulnerability_profiles: List[str] = Field(default_factory=list)
    antispyware_profiles: List[str] = Field(default_factory=list)
    url_filtering_profiles: List[str] = Field(default_factory=list)
    file_blocking_profiles: List[str] = Field(default_factory=list)
    wildfire_analysis_profiles: List[str] = Field(default_factory=list)
    data_filtering_profiles: List[str] = Field(default_factory=list)

    # Advanced / UTM threat-profile compatibility projections.
    security_profile_group: Optional[str] = None
    antivirus: Optional[str] = None
    ips_sensor: Optional[str] = None
    webfilter: Optional[str] = None
    application_list: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    application_categories: List[str] = Field(default_factory=list)
    internet_service: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        data = move_object_extension(data, (
            "policy_package_uid", "policy_package_name", "access_layer_uid",
            "access_layer_name", "access_layer_inline", "access_layer_parent_uid",
            "access_layer_parent_rule_uid", "checkpoint_domain_uid",
            "checkpoint_domain_name", "checkpoint_package_uid", "checkpoint_package_name",
            "checkpoint_layer_uid", "checkpoint_layer_name", "checkpoint_parent_layer_uid",
            "checkpoint_parent_rule_uid", "checkpoint_section_path", "checkpoint_rule_number",
            "install_on",
        ))
        return move_object_extension(data, (
            "source_utm_status", "source_inspection_mode", "source_timeout_send_rst",
            "source_auto_asic_offload", "source_np_acceleration", "source_port_preserve",
            "source_effective_utm_status", "source_effective_inspection_mode",
            "source_effective_ztna_status", "source_effective_timeout_send_rst",
            "source_effective_auto_asic_offload", "source_effective_np_acceleration",
            "source_effective_port_preserve", "source_policy_expiry",
            "source_effective_policy_expiry", "source_policy_expiry_date",
            "source_policy_expiry_date_utc", "source_schedule_timeout",
            "source_effective_schedule_timeout", "source_reputation_direction",
            "source_effective_reputation_direction", "source_reputation_direction6",
            "source_effective_reputation_direction6", "source_reputation_minimum",
            "source_effective_reputation_minimum", "source_reputation_minimum6",
            "source_effective_reputation_minimum6", "source_match_vip",
            "source_effective_match_vip", "source_match_vip_only",
            "source_effective_match_vip_only", "source_internet_service_status",
            "source_internet_service_settings", "source_vpn_tunnel",
            "source_identity_based_route", "source_ztna_status", "source_ztna_ems_tags",
            "source_ztna_device_ownership", "source_ztna_ems_tags_secondary",
            "source_ztna_geo_tags", "source_ztna_policy_redirect",
            "source_ztna_tags_match_logic", "source_attachments",
            "destination_attachments",
        ))

    @model_validator(mode="after")
    def normalize_policy_profile_compatibility(self):
        pairs = (
            ("security_profile_group", "security_profile_groups"),
            ("antivirus", "antivirus_profiles"),
            ("ips_sensor", "vulnerability_profiles"),
            ("webfilter", "url_filtering_profiles"),
        )
        for scalar_field, list_field in pairs:
            values = list(getattr(self, list_field) or [])
            scalar = getattr(self, scalar_field)
            if values:
                setattr(self, scalar_field, values[0] if len(values) == 1 else None)
            elif scalar:
                setattr(self, list_field, [scalar])
        return self

    @property
    def safe_for_target_generation(self) -> bool:
        return (
            self.migration_status == "NORMALIZED"
            and not self.requires_manual_review
            and not self.review_reasons
            and bool(self.source)
            and bool(self.destination)
            and bool(self.service)
        )
class IRDefaultSecurityRule(BaseModel):
    """Configured PAN-OS default-rule overrides without fake match criteria."""

    name: str
    source_context: Optional[str] = None
    source_rule_id: Optional[str] = None
    source_order: int = 0
    rulebase_position: str = "local"
    action: Optional[PolicyAction] = None
    disabled: Optional[bool] = None
    log_start: Optional[bool] = None
    log_end: Optional[bool] = None
    log_setting: Optional[str] = None
    schedule: Optional[str] = None
    security_profile_groups: List[str] = Field(default_factory=list)
    antivirus_profiles: List[str] = Field(default_factory=list)
    vulnerability_profiles: List[str] = Field(default_factory=list)
    antispyware_profiles: List[str] = Field(default_factory=list)
    url_filtering_profiles: List[str] = Field(default_factory=list)
    file_blocking_profiles: List[str] = Field(default_factory=list)
    wildfire_analysis_profiles: List[str] = Field(default_factory=list)
    data_filtering_profiles: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    group_tag: Optional[str] = None
    source_user: List[str] = Field(default_factory=list)
    source_hip: List[str] = Field(default_factory=list)
    destination_hip: List[str] = Field(default_factory=list)
    icmp_unreachable: Optional[str] = None
    negate_source: Optional[str] = None
    negate_destination: Optional[str] = None
    source_options: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFirewallFilterTerm(BaseModel):
    name: str
    source_order: int = 0
    matches: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    from_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFirewallFilter(BaseModel):
    name: str
    family: str = "inet"
    source_context: Optional[str] = None
    terms: List[IRFirewallFilterTerm] = Field(default_factory=list)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IREndpointContextProvider(BaseModel):
    name: str
    provider_type: Optional[str] = None
    enabled: bool = True
    endpoints: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    trust_certificate: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    connection_status: Optional[str] = None

    source_vendor: Optional[str] = None
    source_id: Optional[str] = None
    source_serial: Optional[str] = None
    source_tenant_id: Optional[str] = None
    source_cloud_authentication: Optional[bool] = None

    verifying_ca: Optional[str] = None
    verified_cn: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)

    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    migration_instruction: Optional[str] = None
class IRSessionHelper(BaseModel):
    source_id: int
    name: str
    protocol_number: Optional[int] = None
    protocol_name: Optional[str] = None
    port: Optional[int] = None
    classification: str = "UNKNOWN"
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSessionTTLOverride(BaseModel):
    source_id: int
    protocol_number: Optional[int] = None
    protocol_name: Optional[str] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    timeout_seconds: Optional[int] = None
    timeout_never: bool = False
    refresh_direction: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSessionTTLSettings(BaseModel):
    default_timeout_seconds: Optional[int] = None
    default_never: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFortiGateSourceRule(BaseModel):
    """Sanitized FortiGate-only rule family; never portable target intent."""

    family: str
    source_id: Optional[str] = None
    name: Optional[str] = None
    source_order: int = 0
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    effective_action: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
class IRLocalDeviceAccessRule(IRFortiGateSourceRule):
    """Vendor-neutral management-plane access evidence."""

    interface: Optional[str] = None
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    service_exclusions: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    protocol_exclusions: List[str] = Field(default_factory=list)
    action: Optional[str] = None


class IRIdentityMappingProvider(BaseModel):
    name: str
    provider_type: str
    endpoints: List[str] = Field(default_factory=list)
    domain: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    polling_interval: Optional[int] = None
    mapping_timeout: Optional[int] = None
    source_interfaces: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRManagementAccessPolicy(BaseModel):
    name: str
    services: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    administrators: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    enabled: bool = True
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


IRCheckpointIdentitySource = IRIdentitySource
IRCheckpointAccessRole = IRAccessRole
IRPolicy = IRSecurityPolicy
IRZTNAProvider = IREndpointContextProvider

__all__ = [
    "IRSecurityProfileGroup",
    "IRIdentitySource",
    "IRCheckpointIdentitySource",
    "IRIdentityMappingProvider",
    "IRAccessRole",
    "IRCheckpointAccessRole",
    "IRCheckpointAccessRule",
    "IRCheckpointThreatPreventionRule",
    "IRCheckpointThreatPreventionProfile",
    "IRHTTPSInspectionRule",
    "IRCustomURLCategory",
    "IRIPSSensorExemptIP",
    "IRIPSSensorEntry",
    "IRIPSSensor",
    "IRCheckpointPolicyPackage",
    "IRCheckpointAccessLayer",
    "IRCheckpointDomain",
    "IRCheckpointGlobalAssignment",
    "IRMulticastPolicy",
    "IRSecurityPolicy",
    "IRPolicy",
    "IRDefaultSecurityRule",
    "IRFirewallFilterTerm",
    "IRFirewallFilter",
    "IREndpointContextProvider",
    "IRZTNAProvider",
    "IRSessionHelper",
    "IRSessionTTLOverride",
    "IRSessionTTLSettings",
    "IRFortiGateSourceRule",
    "IRLocalDeviceAccessRule",
    "IRManagementAccessPolicy",
]
