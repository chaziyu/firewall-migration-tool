from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class CPObject(BaseModel):
    uid: str
    name: str
    type: str  # host, network, address-range, group, service-tcp, service-udp, service-group
    ipv4_address: Optional[str] = None
    subnet4: Optional[str] = None
    mask_length4: Optional[int] = None
    ipv4_address_first: Optional[str] = None
    ipv4_address_last: Optional[str] = None
    port: Optional[str] = None
    members: List[Dict[str, Any]] = Field(default_factory=list)
    comments: Optional[str] = None

class CPRule(BaseModel):
    uid: str
    rule_number: int
    name: Optional[str] = None
    action: str = "Accept"
    enabled: bool = True
    source: List[Dict[str, Any]] = Field(default_factory=list)
    destination: List[Dict[str, Any]] = Field(default_factory=list)
    service: List[Dict[str, Any]] = Field(default_factory=list)
    comments: Optional[str] = None
    install_on: List[Dict[str, Any]] = Field(default_factory=list)
