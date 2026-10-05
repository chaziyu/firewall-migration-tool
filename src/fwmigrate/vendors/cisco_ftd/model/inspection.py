"""Vendor-native cisco_ftd inspection models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDIntrusionPolicy(CiscoFTDSourceRecord):
    description: Optional[str] = None
    variable_set: Optional[CiscoFTDReference] = None
    base_policy: Optional[CiscoFTDReference] = None
    snort_version: Optional[str] = None


class CiscoFTDIntrusionRuleGroup(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    description: Optional[str] = None


class CiscoFTDIntrusionRuleBehavior(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    rule_id: Optional[str] = None
    rule_reference: Optional[CiscoFTDReference] = None
    rule_group: Optional[CiscoFTDReference] = None
    state: Optional[Any] = None
    action: Optional[Any] = None
    enabled: Optional[bool] = None


class CiscoFTDIntrusionRuleOverride(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    rule_id: Optional[str] = None
    rule_reference: Optional[CiscoFTDReference] = None
    state: Optional[Any] = None
    action: Optional[Any] = None


class CiscoFTDDecryptionRule(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    position: Optional[int] = None
    collection_order: Optional[int] = None
    enabled: Optional[bool] = None
    action: Optional[Any] = None
    source_networks: Optional[List[CiscoFTDReference]] = None
    destination_networks: Optional[List[CiscoFTDReference]] = None
    source_ports: Optional[List[CiscoFTDReference]] = None
    destination_ports: Optional[List[CiscoFTDReference]] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    tls_conditions: Optional[Dict[str, Any]] = None
    certificate_status_conditions: Optional[Dict[str, Any]] = None


class CiscoFTDDecryptionPolicy(CiscoFTDSourceRecord):
    description: Optional[str] = None
    rules: Optional[List[CiscoFTDDecryptionRule]] = None
    default_action: Optional[Any] = None
    undecryptable_action: Optional[Any] = None
    advanced_settings: Optional[Dict[str, Any]] = None


class CiscoFTDDNSRule(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    position: Optional[int] = None
    collection_order: Optional[int] = None
    enabled: Optional[bool] = None
    action: Optional[Any] = None
    source_zones: Optional[List[CiscoFTDReference]] = None
    destination_zones: Optional[List[CiscoFTDReference]] = None
    source_networks: Optional[List[CiscoFTDReference]] = None
    destination_networks: Optional[List[CiscoFTDReference]] = None
    networks: Optional[List[CiscoFTDReference]] = None
    vlan_tags: Optional[List[CiscoFTDReference]] = None
    lists_feeds: Optional[List[CiscoFTDReference]] = None


class CiscoFTDDNSPolicy(CiscoFTDSourceRecord):
    description: Optional[str] = None
    rules: Optional[List[CiscoFTDDNSRule]] = None
    default_action: Optional[Any] = None
    umbrella_settings: Optional[Dict[str, Any]] = None
