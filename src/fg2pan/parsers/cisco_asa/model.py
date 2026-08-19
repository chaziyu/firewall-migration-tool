from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class CiscoInterface(BaseModel):
    name: str
    nameif: Optional[str] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    security_level: Optional[int] = None
    description: Optional[str] = None
    shutdown: bool = False

class CiscoNetworkObject(BaseModel):
    name: str
    type: str  # host, subnet, range, fqdn
    value: str
    description: Optional[str] = None

class CiscoNetworkGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)  # object names, IPs, or nested groups
    description: Optional[str] = None

class CiscoServicePort(BaseModel):
    protocol: str  # tcp, udp, icmp, ip
    port: str  # e.g. "80", "1000-2000"

class CiscoServiceObject(BaseModel):
    name: str
    ports: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None

class CiscoServiceGroup(BaseModel):
    name: str
    protocol: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    service_objects: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None

class CiscoAccessRule(BaseModel):
    id: str
    acl_name: str
    interface: Optional[str] = None
    action: str  # permit, deny
    protocol: str = "ip"
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    log: bool = False
    inactive: bool = False
    remark: Optional[str] = None

class CiscoNATRule(BaseModel):
    name: str
    source_interface: str = "any"
    destination_interface: str = "any"
    type: str = "source"  # static, dynamic, destination
    real_source: Optional[str] = None
    mapped_source: Optional[str] = None
    real_destination: Optional[str] = None
    mapped_destination: Optional[str] = None
    service: Optional[str] = None
    description: Optional[str] = None

class CiscoStaticRoute(BaseModel):
    interface: str
    destination: str
    mask: str
    gateway: str
    metric: int = 1

class CiscoASAConfig(BaseModel):
    hostname: str = "cisco-asa"
    interfaces: List[CiscoInterface] = Field(default_factory=list)
    network_objects: List[CiscoNetworkObject] = Field(default_factory=list)
    network_groups: List[CiscoNetworkGroup] = Field(default_factory=list)
    service_objects: List[CiscoServiceObject] = Field(default_factory=list)
    service_groups: List[CiscoServiceGroup] = Field(default_factory=list)
    access_rules: List[CiscoAccessRule] = Field(default_factory=list)
    nat_rules: List[CiscoNATRule] = Field(default_factory=list)
    static_routes: List[CiscoStaticRoute] = Field(default_factory=list)
