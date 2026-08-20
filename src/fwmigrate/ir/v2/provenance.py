from enum import Enum
from pydantic import BaseModel
from typing import Optional, Any, Dict, List

class FieldStatus(str, Enum):
    FULL = "FULL"
    TRANSFORMED = "TRANSFORMED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    BLOCKED = "BLOCKED"
    IGNORED = "IGNORED"

class Provenance(BaseModel):
    """
    Tracks the origin of an IR component back to its native source.
    """
    source_id: str
    source_type: str
    original_name: Optional[str] = None
    line_number: Optional[int] = None
    conversion_status: FieldStatus
    loss_details: Optional[str] = None
    
    # Stores original raw attributes that couldn't be mapped
    unknown_fields: Dict[str, Any] = {}
