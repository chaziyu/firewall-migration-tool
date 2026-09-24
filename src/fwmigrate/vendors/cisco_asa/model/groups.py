from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import Field
from .base import CiscoSourceModel


class CiscoNamedGroupMember(CiscoSourceModel):
    type: str
    value: str
    raw: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoNamedGroup(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    group_type: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[CiscoNamedGroupMember] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
