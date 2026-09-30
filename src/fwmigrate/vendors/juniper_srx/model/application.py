"""Vendor-native juniper_srx application models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel, JuniperSourceProvenance


class JuniperApplicationTerm(JuniperEffectiveModel):
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


class JuniperApplication(JuniperEffectiveModel):
    name: str
    description: Optional[str] = None
    terms: List[JuniperApplicationTerm] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperApplicationSet(JuniperEffectiveModel):
    name: str
    applications: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)
