from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


class CiscoDiagnostic(BaseModel):
    line_number: int
    section: str
    object_name: Optional[str] = None
    raw_line: str
    severity: str = "error"
    reason: str
    extraction_effect: str = "PARSE_ERROR"
