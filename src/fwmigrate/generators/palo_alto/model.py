from typing import List, Optional
from pydantic import BaseModel, Field

class PANAddressEntry(BaseModel):
    name: str
    ip_netmask: Optional[str] = Field(None, alias="ip-netmask")
    fqdn: Optional[str] = None
    ip_range: Optional[str] = Field(None, alias="ip-range")
    description: Optional[str] = None

class PANAddressGroupEntry(BaseModel):
    name: str
    static: List[str] = Field(default_factory=list)
    dynamic: Optional[str] = None
    description: Optional[str] = None

class PANTcpService(BaseModel):
    port: str

class PANUdpService(BaseModel):
    port: str

class PANServiceProtocol(BaseModel):
    tcp: Optional[PANTcpService] = None
    udp: Optional[PANUdpService] = None

class PANServiceEntry(BaseModel):
    name: str
    protocol: PANServiceProtocol
    description: Optional[str] = None

class PANServiceGroupEntry(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)

class PANRuleEntry(BaseModel):
    name: str
    to_zones: List[str] = Field(default_factory=list)
    from_zones: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    source_user: List[str] = Field(default_factory=lambda: ["any"])
    category: List[str] = Field(default_factory=lambda: ["any"])
    application: List[str] = Field(default_factory=lambda: ["any"])
    service: List[str] = Field(default_factory=lambda: ["any"])
    source_hip: List[str] = Field(default_factory=lambda: ["any"], alias="source-hip")
    destination_hip: List[str] = Field(default_factory=lambda: ["any"], alias="destination-hip")
    action: str = "deny"
    log_start: str = "no"
    log_end: str = "yes"
    disabled: str = "no"
    description: Optional[str] = None
    profile_setting_group: Optional[str] = None

class PANNATRuleEntry(BaseModel):
    name: str
    to_zones: List[str] = Field(default_factory=list)
    from_zones: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: str = "any"
    source_translation: Optional[str] = None
    destination_translation: Optional[str] = None

class PANZoneNetwork(BaseModel):
    layer3: List[str] = Field(default_factory=list)

class PANZoneEntry(BaseModel):
    name: str
    network: PANZoneNetwork

class PANProfileGroupEntry(BaseModel):
    name: str
    virus: List[str] = Field(default_factory=lambda: ["default"])
    vulnerability: List[str] = Field(default_factory=lambda: ["default"])
    spyware: List[str] = Field(default_factory=lambda: ["default"])
    url_filtering: List[str] = Field(default_factory=lambda: ["default"])
    file_blocking: List[str] = Field(default_factory=lambda: ["basic-file-blocking"])
    wildfire_analysis: List[str] = Field(default_factory=lambda: ["default"])

class PANVsysEntry(BaseModel):
    name: str = "vsys1"
    zones: List[PANZoneEntry] = Field(default_factory=list)
    addresses: List[PANAddressEntry] = Field(default_factory=list)
    address_groups: List[PANAddressGroupEntry] = Field(default_factory=list)
    services: List[PANServiceEntry] = Field(default_factory=list)
    service_groups: List[PANServiceGroupEntry] = Field(default_factory=list)
    profile_groups: List[PANProfileGroupEntry] = Field(default_factory=list)
    security_rules: List[PANRuleEntry] = Field(default_factory=list)
    nat_rules: List[PANNATRuleEntry] = Field(default_factory=list)

class PANDeviceConfig(BaseModel):
    hostname: str

class PANConfig(BaseModel):
    """Root model for PAN-OS configuration"""
    version: str = "11.1.0"
    device_config: PANDeviceConfig
    vsys: PANVsysEntry
