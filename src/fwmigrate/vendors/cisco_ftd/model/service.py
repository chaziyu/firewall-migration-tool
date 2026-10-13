"""Vendor-native cisco_ftd service models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDProtocolPortObject(CiscoFTDSourceRecord):
    protocol: Optional[str] = None
    ports: Optional[List[Any]] = None
    port: Optional[Any] = None
    end_port: Optional[Any] = None
    icmp_type: Optional[Any] = None
    icmp_code: Optional[Any] = None
    description: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDPortObjectGroup(CiscoFTDSourceRecord):
    members: Optional[List[CiscoFTDReference]] = None
    description: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None
