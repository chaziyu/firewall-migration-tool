from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class PANScope(BaseModel):
    kind: str
    name: str
    device_name: Optional[str] = None
    vsys: Optional[str] = None
    device_group: Optional[str] = None
    parent_device_group: Optional[str] = None
    rulebase_position: Optional[str] = None

class PANSourceObject(BaseModel):
    domain: str
    source_path: str
    name: Optional[str] = None
    scope: Optional[PANScope] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    raw_xml: Optional[str] = None
