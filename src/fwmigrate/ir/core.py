from typing import List, Optional, Union
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType, MigrationConfidence

class IRMetadata(BaseModel):
    hostname: str
    source_vendor: str = "fortinet"
    target_vendor: Optional[str] = None
    migration_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class IRZone(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class IRInterface(BaseModel):
    name: str
    zone: Optional[str] = None
    ip: Optional[str] = None  # CIDR format: 192.168.1.1/24
    description: Optional[str] = None
    management_profile: Optional[str] = None
    # For subinterfaces/VLANs
    parent: Optional[str] = None
    tag: Optional[int] = None

class IRAddress(BaseModel):
    name: str
    type: AddressType
    value: str  # CIDR, FQDN, range string
    description: Optional[str] = None

class IRAddressGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class IRServicePort(BaseModel):
    protocol: ServiceProtocol
    port: str  # e.g., "443", "80-90"
    
class IRService(BaseModel):
    name: str
    ports: List[IRServicePort] = Field(default_factory=list)
    description: Optional[str] = None

class IRServiceGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class IRSchedule(BaseModel):
    name: str
    start: Optional[str] = None
    end: Optional[str] = None
    days: List[str] = Field(default_factory=list)

class IRSecurityProfileGroup(BaseModel):
    name: str
    antivirus: Optional[str] = None
    vulnerability: Optional[str] = None
    anti_spyware: Optional[str] = None
    url_filtering: Optional[str] = None
    file_blocking: Optional[str] = None
    wildfire: Optional[str] = None
    ssl_decryption: Optional[str] = None
    description: Optional[str] = None

class IRPolicy(BaseModel):
    name: str
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    action: PolicyAction
    description: Optional[str] = None
    log_end: bool = True
    disabled: bool = False
    # Advanced / UTM threat profiles
    security_profile_group: Optional[str] = None
    antivirus: Optional[str] = None
    ips_sensor: Optional[str] = None
    webfilter: Optional[str] = None
    application_list: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    applications: List[str] = Field(default_factory=list)

class IRNATRule(BaseModel):
    name: str
    type: NATType
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: str = "any"
    translated_source: Optional[str] = None
    translated_destination: Optional[str] = None
    description: Optional[str] = None

class IRVPNTunnel(BaseModel):
    name: str
    peer_address: str
    local_interface: str
    ike_version: str = "v1"
    psk: Optional[str] = None
    ike_crypto_profile: str = "default"
    ipsec_crypto_profile: str = "default"
    description: Optional[str] = None

class IRRoute(BaseModel):
    name: str
    destination: str
    interface: Optional[str] = None
    next_hop: Optional[str] = None
    metric: int = 10
    description: Optional[str] = None

class IRAuditEntry(BaseModel):
    id: str
    category: str
    message: str
    confidence: MigrationConfidence
    original_config: Optional[str] = None

class IRConfig(BaseModel):
    metadata: IRMetadata
    zones: List[IRZone] = Field(default_factory=list)
    interfaces: List[IRInterface] = Field(default_factory=list)
    addresses: List[IRAddress] = Field(default_factory=list)
    address_groups: List[IRAddressGroup] = Field(default_factory=list)
    services: List[IRService] = Field(default_factory=list)
    service_groups: List[IRServiceGroup] = Field(default_factory=list)
    schedules: List[IRSchedule] = Field(default_factory=list)
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    policies: List[IRPolicy] = Field(default_factory=list)
    nat_rules: List[IRNATRule] = Field(default_factory=list)
    vpn_tunnels: List[IRVPNTunnel] = Field(default_factory=list)
    routes: List[IRRoute] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
