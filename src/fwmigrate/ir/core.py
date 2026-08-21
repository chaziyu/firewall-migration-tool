from typing import List, Optional, Union
from pydantic import BaseModel, Field, model_validator
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
    alias: Optional[str] = None
    status: bool = True
    vlanid: Optional[int] = None
    pppoe_mode: Optional[str] = None
    pppoe_username: Optional[str] = None

class IRAddress(BaseModel):
    name: str
    type: AddressType
    
    # Typed fields
    subnet: Optional[str] = None
    ip_range_start: Optional[str] = None
    ip_range_end: Optional[str] = None
    fqdn: Optional[str] = None
    mac: Optional[str] = None
    geo_code: Optional[str] = None
    wildcard_mask: Optional[str] = None
    dynamic_filter: Optional[str] = None
    tag_name: Optional[str] = None
    stub_value: Optional[str] = None
    
    # Stub & manual review fields
    original_type: Optional[str] = None
    original_value: Optional[str] = None
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    
    @model_validator(mode="before")
    @classmethod
    def map_value_to_typed_field(cls, data: dict) -> dict:
        if isinstance(data, dict) and "value" in data and "type" in data:
            val = data.pop("value")
            t = data["type"]
            # Enums might be passed as strings or Enum members
            t_val = t.value if hasattr(t, "value") else t
            if t_val in ("network", "host"):
                data.setdefault("subnet", val)
            elif t_val in ("fqdn", "wildcard"):
                data.setdefault("fqdn", val)
            elif t_val == "range":
                if "-" in val:
                    start, end = val.split("-", 1)
                    data.setdefault("ip_range_start", start)
                    data.setdefault("ip_range_end", end)
            elif t_val == "mac":
                data.setdefault("mac", val)
            elif t_val == "geo":
                data.setdefault("geo_code", val)
            elif t_val == "wildcard_mask":
                data.setdefault("wildcard_mask", val)
            elif t_val == "dynamic":
                data.setdefault("dynamic_filter", val)
            elif t_val == "ems_tag":
                data.setdefault("tag_name", val)
            elif t_val == "stub_unsupported":
                data.setdefault("stub_value", val)
        return data
        
    # Graceful degradation fields
    parse_error: Optional[str] = None
    raw_value: Optional[str] = None
    
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    is_ipv6: bool = False
    is_multicast: bool = False

    @property
    def value(self) -> str:
        if self.parse_error is not None:
            return self.raw_value or ""
        
        if self.type in (AddressType.NETWORK, AddressType.HOST) and self.subnet:
            return self.subnet
        elif self.type == AddressType.RANGE and self.ip_range_start and self.ip_range_end:
            return f"{self.ip_range_start}-{self.ip_range_end}"
        elif self.type in (AddressType.FQDN, AddressType.WILDCARD_FQDN) and self.fqdn:
            return self.fqdn
        elif self.type == AddressType.MAC and self.mac:
            return self.mac
        elif self.type == AddressType.GEO and self.geo_code:
            return self.geo_code
        elif self.type == AddressType.WILDCARD_MASK and self.wildcard_mask:
            return self.wildcard_mask
        elif self.type == AddressType.DYNAMIC and self.dynamic_filter:
            return self.dynamic_filter
        elif self.type == AddressType.EMS_TAG and self.tag_name:
            return self.tag_name
        elif self.type == AddressType.STUB_UNSUPPORTED:
            return self.stub_value or self.subnet or "192.0.2.254/32"
            
        return ""

    @model_validator(mode="after")
    def validate_type_fields(self):
        if self.parse_error is not None:
            return self

        if self.type in (AddressType.NETWORK, AddressType.HOST):
            if not self.subnet:
                raise ValueError(f"Address {self.name} of type {self.type} must have 'subnet' defined.")
        elif self.type == AddressType.RANGE:
            if not self.ip_range_start or not self.ip_range_end:
                raise ValueError(f"Address {self.name} of type RANGE must have 'ip_range_start' and 'ip_range_end'.")
        elif self.type in (AddressType.FQDN, AddressType.WILDCARD_FQDN):
            if not self.fqdn:
                raise ValueError(f"Address {self.name} of type {self.type} must have 'fqdn' defined.")
        elif self.type == AddressType.MAC:
            if not self.mac:
                raise ValueError(f"Address {self.name} of type MAC must have 'mac' defined.")
        elif self.type == AddressType.GEO:
            if not self.geo_code:
                raise ValueError(f"Address {self.name} of type GEO must have 'geo_code' defined.")
        elif self.type == AddressType.WILDCARD_MASK:
            if not self.wildcard_mask:
                raise ValueError(f"Address {self.name} of type WILDCARD_MASK must have 'wildcard_mask' defined.")
        elif self.type == AddressType.DYNAMIC:
            if not self.dynamic_filter:
                raise ValueError(f"Address {self.name} of type DYNAMIC must have 'dynamic_filter' defined.")
        elif self.type == AddressType.EMS_TAG:
            if not self.tag_name:
                raise ValueError(f"Address {self.name} of type EMS_TAG must have 'tag_name' defined.")
        elif self.type == AddressType.STUB_UNSUPPORTED:
            pass
                
        return self

class IRAddressGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    is_dynamic: bool = False
    dynamic_filter: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class IRServicePort(BaseModel):
    protocol: ServiceProtocol
    port: str  # e.g., "443", "80-90"
    icmptype: Optional[int] = None
    icmpcode: Optional[int] = None
    
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
    schedule: Optional[str] = None
    log_start: bool = False
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
    internet_service: List[str] = Field(default_factory=list)

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
    translated_port: Optional[str] = None
    description: Optional[str] = None

    @model_validator(mode="after")
    def validate_twice_nat(self):
        if self.type == NATType.TWICE:
            if self.translated_source is None and self.translated_destination is None:
                raise ValueError(f"NAT Rule {self.name} of type TWICE must have at least one translated field defined (source or destination).")
        return self

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

class IRInternetService(BaseModel):
    name: str
    description: Optional[str] = None

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
    internet_services: List[IRInternetService] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
