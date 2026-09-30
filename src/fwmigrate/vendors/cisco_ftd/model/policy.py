"""Vendor-native cisco_ftd policy models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDPrefilterPolicy(CiscoFTDSourceRecord): pass


class CiscoFTDPrefilterRule(CiscoFTDSourceRecord):
    position: Optional[int] = None
    action: Optional[Any] = None
    conditions: Optional[Dict[str, Any]] = None
    references: Optional[List[CiscoFTDReference]] = None


class CiscoFTDPrefilterDefaultAction(CiscoFTDSourceRecord): pass


class CiscoFTDNetworkAnalysisPolicy(CiscoFTDSourceRecord): pass


class CiscoFTDInspectorConfig(CiscoFTDSourceRecord): pass


class CiscoFTDInspectorOverrideConfig(CiscoFTDSourceRecord): pass


class CiscoFTDFileRule(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    position: Optional[int] = None
    collection_order: Optional[int] = None
    enabled: Optional[bool] = None
    action: Optional[Any] = None
    application_protocols: Optional[Any] = None
    transfer_direction: Optional[Any] = None
    file_types: Optional[List[Any]] = None
    malware_inspection: Optional[Any] = None
    file_store: Optional[Any] = None


class CiscoFTDFilePolicy(CiscoFTDSourceRecord):
    description: Optional[str] = None
    rules: Optional[List[CiscoFTDFileRule]] = None


class CiscoFTDVariableSet(CiscoFTDSourceRecord): pass


class CiscoFTDURLCategory(CiscoFTDSourceRecord): pass


class CiscoFTDVLANObject(CiscoFTDSourceRecord): pass


class CiscoFTDAccessControlRule(CiscoFTDSourceRecord):
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    enabled: Optional[bool] = None
    position: Optional[int] = None
    collection_order: Optional[int] = None
    section: Optional[str] = None
    category: Optional[str] = None
    action: Optional[str] = None
    comments: Optional[str] = None
    source_zones: Optional[List[CiscoFTDReference]] = None
    destination_zones: Optional[List[CiscoFTDReference]] = None
    source_networks: Optional[List[CiscoFTDReference]] = None
    destination_networks: Optional[List[CiscoFTDReference]] = None
    source_ports: Optional[List[CiscoFTDReference]] = None
    destination_ports: Optional[List[CiscoFTDReference]] = None
    source_dynamic_objects: Optional[List[CiscoFTDReference]] = None
    destination_dynamic_objects: Optional[List[CiscoFTDReference]] = None
    vlan_tags: Optional[List[CiscoFTDReference]] = None
    source_security_group_tags: Optional[List[CiscoFTDReference]] = None
    destination_security_group_tags: Optional[List[CiscoFTDReference]] = None
    realm: Optional[CiscoFTDReference] = None
    realm_users: Optional[List[CiscoFTDReference]] = None
    users: Optional[List[CiscoFTDReference]] = None
    user_groups: Optional[List[CiscoFTDReference]] = None
    applications: Optional[List[CiscoFTDReference]] = None
    application_filters: Optional[List[CiscoFTDReference]] = None
    inline_application_filters: Optional[List[CiscoFTDReference]] = None
    urls: Optional[Dict[str, Any]] = None
    url_categories: Optional[List[CiscoFTDReference]] = None
    time_range: Optional[CiscoFTDReference] = None
    intrusion_policy: Optional[CiscoFTDReference] = None
    variable_set: Optional[CiscoFTDReference] = None
    file_policy: Optional[CiscoFTDReference] = None
    log_begin: Optional[bool] = None
    log_end: Optional[bool] = None
    logging: Optional[Dict[str, Any]] = None


class CiscoFTDAccessControlPolicy(CiscoFTDSourceRecord):
    rules: Optional[List[CiscoFTDAccessControlRule]] = None
    description: Optional[str] = None
    inherit: Optional[bool] = None
    base_policy: Optional[CiscoFTDReference] = None
    default_action: Optional[CiscoFTDReference] = None
    prefilter_policy: Optional[CiscoFTDReference] = None
    network_analysis_policy: Optional[CiscoFTDReference] = None
    decryption_policy: Optional[CiscoFTDReference] = None
    dns_policy: Optional[CiscoFTDReference] = None
    identity_policy: Optional[CiscoFTDReference] = None
    logging_settings: Optional[Any] = None


class CiscoFTDAccessControlLoggingSetting(CiscoFTDSourceRecord):
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None


class CiscoFTDSecurityIntelligencePolicy(CiscoFTDSourceRecord):
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None


class CiscoFTDIdentityPolicy(CiscoFTDSourceRecord): pass


class CiscoFTDAccessControlDefaultAction(CiscoFTDSourceRecord):
    policy_id: Optional[str] = None
    action: Optional[str] = None


class CiscoFTDAccessPolicyInheritanceSettings(CiscoFTDSourceRecord):
    policy_id: Optional[str] = None
    base_policy: Optional[CiscoFTDReference] = None
    description: Optional[str] = None


class CiscoFTDPolicyAssignment(CiscoFTDSourceRecord):
    policy: Optional[CiscoFTDReference] = None
    targets: Optional[List[CiscoFTDReference]] = None


class CiscoFTDRecurringTimeRangeEntry(BaseModel):
    recurrence_type: Optional[str] = None
    days: Optional[List[str]] = None
    daily_start_time: Optional[str] = None
    daily_end_time: Optional[str] = None
    range_start_day: Optional[str] = None
    range_start_time: Optional[str] = None
    range_end_day: Optional[str] = None
    range_end_time: Optional[str] = None
    explicit_fields: List[str] = Field(default_factory=list)
    raw_extra: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDTimeRange(CiscoFTDSourceRecord):
    description: Optional[str] = None
    absolute_start_date_time: Optional[str] = None
    absolute_end_date_time: Optional[str] = None
    recurrence_entries: Optional[List[CiscoFTDRecurringTimeRangeEntry]] = None
