from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CiscoSourceModel(BaseModel):
    explicit_fields: set[str] = Field(default_factory=set)
    raw_extra: Dict[str, Any] = Field(default_factory=dict)


class CiscoSourceRecord(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "SOURCE_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
