"""Vendor-native cisco_ftd base models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CiscoFTDSourceRecord(BaseModel):
    """Vendor-native record retained from one authoritative FTD source plane."""

    name: str
    source_id: Optional[str] = None
    source_plane: str
    source_context: Optional[str] = None
    domain_id: Optional[str] = None
    device_id: Optional[str] = None
    explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    raw_extra: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDReference(BaseModel):
    source_id: Optional[str] = None
    name: Optional[str] = None
    source_type: Optional[str] = None
    value: Optional[Any] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
