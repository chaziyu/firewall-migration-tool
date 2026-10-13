"""Vendor-native juniper_srx address models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel, JuniperSourceProvenance


class JuniperAddress(JuniperEffectiveModel):
    name: str
    address_book: str
    zone: Optional[str] = None
    type: Optional[str] = None  # ip-prefix, dns-name, dns-address, range-address, wildcard-address
    prefix: Optional[str] = None
    fqdn: Optional[str] = None
    range_start: Optional[str] = None
    range_end: Optional[str] = None
    wildcard: Optional[str] = None
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperAddressSetMember(JuniperEffectiveModel):
    name: str
    member_type: str  # address | address-set
    source_path: Optional[str] = None


class JuniperAddressSet(JuniperEffectiveModel):
    name: str
    address_book: str
    zone: Optional[str] = None
    members: List[JuniperAddressSetMember] = Field(default_factory=list)
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperAddressBook(JuniperEffectiveModel):
    name: str
    attached_zones: List[str] = Field(default_factory=list)
    addresses: Dict[str, JuniperAddress] = Field(default_factory=dict)
    address_sets: Dict[str, JuniperAddressSet] = Field(default_factory=dict)
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)
