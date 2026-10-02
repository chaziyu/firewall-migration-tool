"""Vendor-native juniper_srx nat models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel


class JuniperNATPool(JuniperEffectiveModel):
    name: str
    nat_type: str  # source | destination
    routing_instance: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)
    ports: List[str] = Field(default_factory=list)
    address_ranges: List[Dict[str, str]] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperPersistentNAT(JuniperEffectiveModel):
    address_mapping: Optional[bool] = None
    inactivity_timeout: Optional[int] = None
    max_session_number: Optional[int] = None
    permit: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATContext(BaseModel):
    zones: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    routing_instances: List[str] = Field(default_factory=list)


class JuniperNATMatch(JuniperEffectiveModel):
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


class JuniperNATRule(JuniperEffectiveModel):
    name: str
    nat_type: str  # source | destination | static
    match: JuniperNATMatch = Field(default_factory=JuniperNATMatch)
    action: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    disabled: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNATRuleSet(JuniperEffectiveModel):
    name: str
    nat_type: str  # source | destination | static
    from_context: JuniperNATContext = Field(default_factory=JuniperNATContext)
    to_context: Optional[JuniperNATContext] = None
    rules: List[JuniperNATRule] = Field(default_factory=list)
    description: Optional[str] = None
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
