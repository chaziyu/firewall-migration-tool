from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

class FeatureSupport(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    EMULATED = "EMULATED"

class FieldCapability(BaseModel):
    """
    Describes the support level and constraints of a specific configuration field.
    """
    support: FeatureSupport
    max_length: Optional[int] = None
    allowed_characters: Optional[str] = None
    max_items: Optional[int] = None # For lists
    notes: Optional[str] = None

class ObjectCapability(BaseModel):
    """
    Describes the capability of a configuration object (e.g. SecurityRule, AddressGroup).
    """
    support: FeatureSupport
    fields: Dict[str, FieldCapability] = Field(default_factory=dict)
    max_instances: Optional[int] = None
    notes: Optional[str] = None

class VendorCapabilityProfile(BaseModel):
    """
    A data-driven capability matrix for a specific vendor and OS version.
    Used to calculate structural loss during migration.
    """
    vendor_id: str
    os_version: str
    objects: Dict[str, ObjectCapability] = Field(default_factory=dict)
