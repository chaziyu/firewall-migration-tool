"""Vendor-native juniper_srx vpn models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel


class JuniperIKEProposal(JuniperEffectiveModel):
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


class JuniperIKEPolicy(JuniperEffectiveModel):
    name: str
    mode: Optional[str] = None
    proposal_set: Optional[str] = None
    proposals: List[str] = Field(default_factory=list)
    has_pre_shared_key: Optional[bool] = None
    certificate_reference: Optional[str] = None
    local_certificate: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIKEGateway(JuniperEffectiveModel):
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


class JuniperIPSecProposal(JuniperEffectiveModel):
    name: str
    description: Optional[str] = None
    protocol: Optional[str] = None  # esp | ah
    authentication_algorithm: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    lifetime_kilobytes: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecPolicy(JuniperEffectiveModel):
    name: str
    proposal_set: Optional[str] = None
    proposals: List[str] = Field(default_factory=list)
    pfs_group: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperTrafficSelectorTerm(JuniperEffectiveModel):
    name: str
    local_ip: List[str] = Field(default_factory=list)
    remote_ip: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    local_port: List[str] = Field(default_factory=list)
    remote_port: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperTrafficSelector(JuniperEffectiveModel):
    name: str
    local_ip: List[str] = Field(default_factory=list)
    remote_ip: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    local_port: List[str] = Field(default_factory=list)
    remote_port: List[str] = Field(default_factory=list)
    terms: Dict[str, JuniperTrafficSelectorTerm] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperVPNMonitor(BaseModel):
    destination_ip: Optional[str] = None
    source_interface: Optional[str] = None
    options: Dict[str, Any] = Field(default_factory=dict)


class JuniperIPSecVPN(JuniperEffectiveModel):
    name: str
    bind_interface: Optional[str] = None
    ike_gateway: Optional[str] = None
    ipsec_policy: Optional[str] = None
    establish_tunnels: Optional[str] = None
    traffic_selectors: Dict[str, JuniperTrafficSelector] = Field(default_factory=dict)
    vpn_monitor: Optional[JuniperVPNMonitor] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperVPNConfig(BaseModel):
    ike_proposals: Dict[str, JuniperIKEProposal] = Field(default_factory=dict)
    ike_policies: Dict[str, JuniperIKEPolicy] = Field(default_factory=dict)
    ike_gateways: Dict[str, JuniperIKEGateway] = Field(default_factory=dict)
    ipsec_proposals: Dict[str, JuniperIPSecProposal] = Field(default_factory=dict)
    ipsec_policies: Dict[str, JuniperIPSecPolicy] = Field(default_factory=dict)
    ipsec_vpns: Dict[str, JuniperIPSecVPN] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRemoteAccessApplicationBypassTerm(BaseModel):
    name: str
    description: Optional[str] = None
    domain_names: List[str] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRemoteAccessClientConfig(BaseModel):
    name: str
    application_bypass_terms: Dict[str, JuniperRemoteAccessApplicationBypassTerm] = Field(default_factory=dict)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRemoteAccessProfile(BaseModel):
    name: str
    access_profile: Optional[str] = None
    client_config: Optional[str] = None
    ipsec_vpn: Optional[str] = None
    multi_access: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRemoteAccessConfig(BaseModel):
    profiles: Dict[str, JuniperRemoteAccessProfile] = Field(default_factory=dict)
    client_configs: Dict[str, JuniperRemoteAccessClientConfig] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
