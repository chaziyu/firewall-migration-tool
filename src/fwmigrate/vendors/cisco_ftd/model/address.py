"""Vendor-native cisco_ftd address models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDNetworkAddress(CiscoFTDSourceRecord):
    address_type: Optional[str] = None
    value: Optional[Any] = None
    description: Optional[str] = None
    fqdn_lookup_type: Optional[str] = None
    address_family: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDNetworkAddressOverride(CiscoFTDSourceRecord):
    parent: Optional[CiscoFTDReference] = None
    target: Optional[CiscoFTDReference] = None
    address_type: Optional[str] = None
    value: Optional[Any] = None
    overridable: Optional[bool] = None


class CiscoFTDNetworkGroup(CiscoFTDSourceRecord):
    members: Optional[List[CiscoFTDReference]] = None
    literal_members: Optional[List[CiscoFTDReference]] = None
    description: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None
