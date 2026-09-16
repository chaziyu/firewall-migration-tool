# Canonical IR address domain models

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from fwmigrate.ir.enums import AddressType
from .extension_models import (
    IRCheckPointObjectCompatibilityMixin,
    IRCheckPointObjectExtension,
    IRFortiOSAddressCompatibilityMixin,
    IRFortiOSAddressGroupCompatibilityMixin,
    IRFortiOSAddressExtension,
    move_object_extension,
)


class IRAddressTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRMACAddressEntry(BaseModel):
    start: str
    end: Optional[str] = None
class IRAddress(IRCheckPointObjectCompatibilityMixin, IRFortiOSAddressCompatibilityMixin, BaseModel):
    name: str
    type: AddressType
    source_context: Optional[str] = None

    # Source provenance and extraction-only metadata. Target generators must
    # not interpret source-only fields as portable address semantics.
    source_uuid: Optional[str] = None
    vendor_extension: Optional[IRCheckPointObjectExtension | IRFortiOSAddressExtension] = None
    source_section: Optional[str] = None
    address_family: Optional[str] = None
    source_type: Optional[str] = None
    source_list_entries: List[str] = Field(default_factory=list)
    source_tagging_entries: List[IRAddressTaggingEntry] = Field(default_factory=list)
    associated_interface: Optional[str] = None
    allow_routing: Optional[bool] = None
    source_color: Optional[int] = None
    source_interface: Optional[str] = None
    resolved_interface_subnet: Optional[str] = None
    interface_reference_resolved: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    
    # Typed fields
    subnet: Optional[str] = None
    ip_range_start: Optional[str] = None
    ip_range_end: Optional[str] = None
    fqdn: Optional[str] = None
    mac: Optional[str] = None
    mac_entries: List[IRMACAddressEntry] = Field(default_factory=list)
    geo_code: Optional[str] = None
    wildcard_mask: Optional[str] = None
    dynamic_filter: Optional[str] = None
    tag_name: Optional[str] = None
    stub_value: Optional[str] = None
    
    # Stub & manual review fields
    original_type: Optional[str] = None
    original_value: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        data = move_object_extension(
            data,
            (
                "checkpoint_domain_uid", "checkpoint_domain_name",
                "checkpoint_origin_scope", "global_source_uid",
                "global_source_name", "local_override_uid", "assignment_uid",
            ),
        )
        return move_object_extension(
            data,
            (
                "source_hw_model", "source_hw_vendor", "source_cache_ttl",
                "source_clearpass_spt", "source_epg_name", "source_organization",
                "source_os", "source_policy_group", "source_route_tag", "source_sdn",
                "source_sdn_addr_type", "source_sdn_tag", "source_node_ip_only",
                "source_obj_id", "source_sub_type", "source_obj_tag", "source_tag_type",
                "source_obj_type", "source_dirty", "source_subnet_name", "source_sw_version",
                "source_tag_detection_level", "source_tenant",
                "source_fsso_group", "source_fabric_object_setting",
                "source_effective_defaults", "source_template",
                "source_template_reference_resolved",
            ),
        )
    
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
            elif t_val == "special":
                data.setdefault("original_value", val)
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
        elif self.type == AddressType.MAC:
            if self.mac:
                return self.mac
            return "; ".join(
                f"{entry.start}-{entry.end}" if entry.end else entry.start
                for entry in self.mac_entries
            )
        elif self.type == AddressType.GEO and self.geo_code:
            return self.geo_code
        elif self.type == AddressType.WILDCARD_MASK and self.wildcard_mask:
            return self.wildcard_mask
        elif self.type == AddressType.DYNAMIC and self.dynamic_filter:
            return self.dynamic_filter
        elif self.type == AddressType.EMS_TAG and self.tag_name:
            return self.tag_name
        elif self.type == AddressType.SPECIAL:
            if self.original_value is not None:
                return self.original_value
            return self.name
        elif self.type == AddressType.STUB_UNSUPPORTED:
            return self.stub_value or self.subnet or ""
            
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
            if not self.mac and not self.mac_entries:
                raise ValueError(f"Address {self.name} of type MAC must have 'mac' or 'mac_entries' defined.")
        elif self.type == AddressType.GEO:
            if not self.geo_code:
                raise ValueError(f"Address {self.name} of type GEO must have 'geo_code' defined.")
        elif self.type == AddressType.WILDCARD_MASK:
            if not self.wildcard_mask:
                raise ValueError(f"Address {self.name} of type WILDCARD_MASK must have 'wildcard_mask' defined.")
        elif self.type == AddressType.DYNAMIC:
            if not self.dynamic_filter and not any((
                self.source_sw_version,
                self.source_tag_detection_level,
                self.source_tenant,
                self.source_sdn,
                self.source_organization,
                self.source_os,
                self.source_policy_group,
            )):
                raise ValueError(f"Address {self.name} of type DYNAMIC must have a dynamic criterion defined.")
        elif self.type == AddressType.EMS_TAG:
            if not self.tag_name:
                raise ValueError(f"Address {self.name} of type EMS_TAG must have 'tag_name' defined.")
        elif self.type == AddressType.SPECIAL:
            pass
        elif self.type == AddressType.STUB_UNSUPPORTED:
            pass
                
        return self
class IRAddressGroupTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAddressGroup(IRFortiOSAddressGroupCompatibilityMixin, BaseModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    source_direct_members: List[str] = Field(default_factory=list)
    source_nested_group_members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    is_dynamic: bool = False
    dynamic_filter: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    # Source metadata used for partially normalized dynamic/EMS objects.
    source_uuid: Optional[str] = None
    vendor_extension: Optional[IRFortiOSAddressExtension] = None
    associated_interface: Optional[str] = None
    allow_routing: Optional[bool] = None
    source_color: Optional[int] = None
    source_category: Optional[str] = None
    source_section: Optional[str] = None
    address_family: Optional[str] = None
    exclusion_enabled: bool = False
    exclude_members: List[str] = Field(default_factory=list)
    source_tagging_entries: List[IRAddressGroupTaggingEntry] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        return move_object_extension(data, (
            "source_fabric_object_setting", "source_group_type", "source_exclude_setting",
            "source_sub_type", "source_obj_tag", "source_tag_type", "source_obj_type",
            "source_dirty",
        ))

__all__ = [
    "IRAddressTaggingEntry",
    "IRMACAddressEntry",
    "IRAddress",
    "IRAddressGroup",
    "IRAddressGroupTaggingEntry",
]
