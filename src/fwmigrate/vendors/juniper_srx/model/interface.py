"""Vendor-native juniper_srx interface models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveCandidate, JuniperEffectiveModel, JuniperEffectiveProvenance


class JuniperInterfaceAddress(JuniperEffectiveModel):
    family: str  # inet or inet6
    address: str
    primary: Optional[bool] = None
    preferred: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: Optional[JuniperEffectiveProvenance] = None
    candidate_history: List[JuniperEffectiveCandidate] = Field(default_factory=list)


class JuniperInterfaceUnit(JuniperEffectiveModel):
    unit: str
    description: Optional[str] = None
    mtu: Optional[int] = None
    vlan_id: Optional[int] = None
    encapsulation: Optional[str] = None
    family_attributes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    filters: List[Dict[str, Any]] = Field(default_factory=list)
    vrrp: List[Dict[str, Any]] = Field(default_factory=list)
    addresses: List[JuniperInterfaceAddress] = Field(default_factory=list)
    disabled: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    field_provenance: Dict[str, JuniperEffectiveProvenance] = Field(default_factory=dict)
    field_candidate_history: Dict[str, List[JuniperEffectiveCandidate]] = Field(default_factory=dict)


class JuniperScreenOption(BaseModel):
    path: List[str]
    values: List[str] = Field(default_factory=list)


class JuniperScreenProfile(BaseModel):
    name: str
    options: List[JuniperScreenOption] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperFirewallFilterTerm(BaseModel):
    name: str
    source_order: int = 0
    matches: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    from_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperFirewallFilter(BaseModel):
    name: str
    family: str
    terms: List[JuniperFirewallFilterTerm] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperInterface(JuniperEffectiveModel):
    name: str
    description: Optional[str] = None
    disabled: Optional[bool] = None
    mtu: Optional[int] = None
    speed: Optional[str] = None
    link_mode: Optional[str] = None
    encapsulation: Optional[str] = None
    physical_link: Dict[str, Any] = Field(default_factory=dict)
    aggregate_parent: Optional[str] = None
    aggregate_options: List[Dict[str, Any]] = Field(default_factory=list)
    redundant_parent: Optional[str] = None
    redundancy_group: Optional[str] = None
    units: Dict[str, JuniperInterfaceUnit] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
