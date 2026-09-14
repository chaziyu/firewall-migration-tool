# Canonical IR common domain models

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class IRExecutionContext(BaseModel):
    vdom: str = "root"
    scope: str = "vdom"
    central_nat: Optional[str] = None
    ngfw_mode: Optional[str] = None
    opmode: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "IRExecutionContext",
]
