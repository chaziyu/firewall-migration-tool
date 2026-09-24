from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import Field
from .base import CiscoSourceModel


class CiscoTimeRangeClause(CiscoSourceModel):
    clause_type: str
    raw: str
    start: Optional[str] = None
    end: Optional[str] = None
    days: List[str] = Field(default_factory=list)
    end_days: List[str] = Field(default_factory=list)
    source_order: int = 0


class CiscoTimeRange(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    clauses: List[CiscoTimeRangeClause] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
