from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoSourceModel, CiscoSourceRecord


class CiscoAllocatedInterface(CiscoSourceModel):
    physical_interface: str
    mapped_name: Optional[str] = None
    range_expression: Optional[str] = None
    source_order: int = 0
    raw: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoMultiContextSystem(BaseModel):
    admin_context_name: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoASAContext(CiscoSourceRecord):
    allocated_interface_entries: List[CiscoAllocatedInterface] = Field(default_factory=list)
    config_url: Optional[str] = None
    admin_context: Optional[bool] = None
    allocated_interfaces: List[str] = Field(default_factory=list)
    resource_class: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
