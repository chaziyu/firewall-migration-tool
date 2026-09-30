"""Vendor-native juniper_srx policy models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel, JuniperSourceProvenance


class JuniperPolicy(JuniperEffectiveModel):
    name: str
    policy_scope: str  # zone | global
    from_zones: List[str] = Field(default_factory=list)
    to_zones: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    source_address_excluded: Optional[bool] = None
    destination_address_excluded: Optional[bool] = None
    dynamic_applications: List[str] = Field(default_factory=list)
    source_identities: List[str] = Field(default_factory=list)
    source_end_user_profiles: List[str] = Field(default_factory=list)
    scheduler_name: Optional[str] = None
    action: Optional[str] = None  # permit, deny, reject, or None
    log_session_init: Optional[bool] = None
    log_session_close: Optional[bool] = None
    logging_options: List[Dict[str, Any]] = Field(default_factory=list)
    count: Optional[bool] = None
    description: Optional[str] = None
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


class JuniperUTMAntivirusProfile(BaseModel):
    name: str
    engine_type: Optional[str] = None
    scan_behavior: Dict[str, Any] = Field(default_factory=dict)
    fallback_behavior: Dict[str, Any] = Field(default_factory=dict)
    file_controls: List[str] = Field(default_factory=list)
    mime_types: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperUTMWebFilteringProfile(BaseModel):
    name: str
    url_categories: List[str] = Field(default_factory=list)
    custom_url_lists: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    logging: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperUTMContentFilteringProfile(BaseModel):
    name: str
    syntax_variant: Optional[str] = None
    content_types: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperUTMAntiSpamProfile(BaseModel):
    name: str
    servers: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
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
