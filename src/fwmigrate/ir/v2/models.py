from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from fwmigrate.ir.enums import ServiceProtocol, PolicyAction
from fwmigrate.ir.v2.provenance import Provenance, FieldStatus

class IRComponent(BaseModel):
    """
    Base class for all IR v2 components.
    Requires provenance to guarantee that no source data is silently lost.
    """
    name: str
    provenance: Provenance

class ZoneV2(IRComponent):
    interfaces: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class AddressV2(IRComponent):
    type: str # 'ip-netmask', 'ip-range', 'fqdn'
    value: str
    description: Optional[str] = None

class AddressGroupV2(IRComponent):
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class ServiceV2(IRComponent):
    protocol: ServiceProtocol
    port_range: str
    description: Optional[str] = None

class ServiceGroupV2(IRComponent):
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class SecurityRuleV2(IRComponent):
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    action: PolicyAction
    disabled: bool = False
    description: Optional[str] = None
    log_end: bool = True

class IRConfigV2(BaseModel):
    """
    The canonical v2 Intermediate Representation.
    """
    zones: List[ZoneV2] = Field(default_factory=list)
    addresses: List[AddressV2] = Field(default_factory=list)
    address_groups: List[AddressGroupV2] = Field(default_factory=list)
    services: List[ServiceV2] = Field(default_factory=list)
    service_groups: List[ServiceGroupV2] = Field(default_factory=list)
    policies: List[SecurityRuleV2] = Field(default_factory=list)
    
    # Track unsupported/unmapped global config
    global_unknown_fields: Dict[str, Any] = Field(default_factory=dict)
