from __future__ import annotations
from typing import List, Optional
from pydantic import Field
from .base import CiscoSourceModel, CiscoSourceRecord


class CiscoDHCPOption(CiscoSourceModel):
    code: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    value_type: Optional[str] = None
    encoding: Optional[str] = None


class CiscoDHCPGlobalSettings(CiscoSourceRecord):
    source_order: int = 0
    dns_servers: List[str] = Field(default_factory=list)
    wins_servers: List[str] = Field(default_factory=list)
    domain_name: Optional[str] = None
    lease_seconds: Optional[int] = None
    ping_timeout: Optional[int] = None
    options: List[CiscoDHCPOption] = Field(default_factory=list)


class CiscoDHCPServer(CiscoSourceRecord):
    interface: Optional[str] = None
    pool: Optional[str] = None
    pool_start: Optional[str] = None
    pool_end: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    wins_servers: List[str] = Field(default_factory=list)
    ping_timeout: Optional[int] = None
    auto_config: Optional[str] = None
    dns_update: Optional[str] = None
    reservations: List["CiscoDHCPReservation"] = Field(default_factory=list)
    domain_name: Optional[str] = None
    lease_seconds: Optional[int] = None
    options: List[CiscoDHCPOption] = Field(default_factory=list)
    enabled: Optional[bool] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDHCPRelayServer(CiscoSourceModel):
    server: str
    interface: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDHCPReservation(CiscoSourceModel):
    ip: str
    mac: str
    interface: str
    source_order: int = 0


class CiscoDHCPRelay(CiscoSourceRecord):
    interface: Optional[str] = None
    server: Optional[str] = None
    servers: List[str] = Field(default_factory=list)
    server_entries: List[CiscoDHCPRelayServer] = Field(default_factory=list)
    enabled_interfaces: List[str] = Field(default_factory=list)
    timeout: Optional[int] = None
    options: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)
