from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ServiceProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"
    IP = "ip"


class IRServiceObject(BaseModel):
    name: str
    protocol: ServiceProtocol
    port: str
    description: Optional[str] = None


class IRNatType(str, Enum):
    """Deprecated NAT enum retained only for legacy helper compatibility tests."""
    SNAT_DIPP = "snat_dipp"         # Dynamic IP and Port
    SNAT_STATIC = "snat_static"     # Static 1-to-1 Source Translation
    DNAT_STATIC = "dnat_static"     # Static Destination Translation


class IRNatRule(BaseModel):
    """Deprecated: use fwmigrate.ir.core.IRNATRule for production workflows."""
    name: str
    nat_type: IRNatType
    from_zones: List[str] = Field(default_factory=lambda: ["any"])
    to_zones: List[str] = Field(default_factory=lambda: ["any"])             # Pre-NAT zone for PAN-OS
    sources: List[str] = Field(default_factory=lambda: ["any"])
    destinations: List[str] = Field(default_factory=lambda: ["any"])         # Pre-NAT IPs / Objects
    service: str = "any"                                                     # Pre-NAT Service match
    translated_sources: Optional[List[str]] = None
    translated_destinations: Optional[List[str]] = None                     # Post-NAT IPs
    translated_port: Optional[str] = None                                    # Post-NAT Port (PAT)
    description: Optional[str] = None


class IRSecurityRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default_factory=lambda: ["any"])
    to_zones: List[str] = Field(default_factory=lambda: ["any"])             # Post-NAT zone for PAN-OS
    sources: List[str] = Field(default_factory=lambda: ["any"])
    destinations: List[str] = Field(default_factory=lambda: ["any"])         # Pre-NAT IPs / Objects
    services: List[str] = Field(default_factory=lambda: ["any"])             # Pre-NAT Services
    action: str = "deny"
    description: Optional[str] = None
