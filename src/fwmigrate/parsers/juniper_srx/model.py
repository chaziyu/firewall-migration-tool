from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class JuniperAddress(BaseModel):
    name: str
    zone: Optional[str] = None  # None if global
    value: str  # e.g. "192.168.1.0/24", "10.1.1.1/32", or dns-name
    type: str = "ip-prefix"  # ip-prefix, dns-name, range
    description: Optional[str] = None

class JuniperAddressSet(BaseModel):
    name: str
    zone: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class JuniperApplication(BaseModel):
    name: str
    protocol: str = "tcp"
    destination_port: Optional[str] = None
    description: Optional[str] = None

class JuniperApplicationSet(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class JuniperPolicy(BaseModel):
    name: str
    from_zone: str
    to_zone: str
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    action: str = "permit"  # permit, deny, reject
    description: Optional[str] = None
    disabled: bool = False
    log_session_close: bool = False

class JuniperSRXConfig(BaseModel):
    hostname: str = "juniper-srx"
    zones: Dict[str, List[str]] = Field(default_factory=dict)  # zone_name -> [interfaces]
    addresses: List[JuniperAddress] = Field(default_factory=list)
    address_sets: List[JuniperAddressSet] = Field(default_factory=list)
    applications: List[JuniperApplication] = Field(default_factory=list)
    application_sets: List[JuniperApplicationSet] = Field(default_factory=list)
    policies: List[JuniperPolicy] = Field(default_factory=list)
    routes: List[Dict[str, Any]] = Field(default_factory=list)
