from dataclasses import dataclass, field
from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

class FeatureSupport(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    EMULATED = "EMULATED"


class CapabilityStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass
class CapabilityIssue:
    feature: str
    status: CapabilityStatus
    reason: str
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    target_vendor: str = ""
    blocks_generation: bool = False

    def __post_init__(self) -> None:
        self.status = CapabilityStatus(self.status)

    @property
    def severity(self) -> str:
        if self.blocks_generation:
            return "CRITICAL"
        if self.status == CapabilityStatus.UNSUPPORTED:
            return "HIGH"
        if self.status == CapabilityStatus.PARTIAL:
            return "MEDIUM"
        return "LOW"

    @property
    def category(self) -> str:
        return "CAPABILITY_MISMATCH" if self.status == CapabilityStatus.UNSUPPORTED else "DATA_LOSS"

    @property
    def source_object(self) -> str:
        return ":".join(value for value in (self.object_type, self.object_id) if value) or self.feature

    @property
    def target_object(self) -> Optional[str]:
        return f"{self.target_vendor}:{self.feature}" if self.target_vendor else None

    @property
    def message(self) -> str:
        return self.reason

    @property
    def blocking(self) -> bool:
        return self.blocks_generation


@dataclass
class CapabilityAnalysisResult:
    issues: List[CapabilityIssue] = field(default_factory=list)
    supported_count: int = 0
    partial_count: int = 0
    unsupported_count: int = 0
    manual_review_count: int = 0
    generation_blocked: bool = False

    def __post_init__(self) -> None:
        for issue in self.issues:
            issue.status = CapabilityStatus(issue.status)
        self.supported_count = sum(i.status == CapabilityStatus.SUPPORTED for i in self.issues)
        self.partial_count = sum(i.status == CapabilityStatus.PARTIAL for i in self.issues)
        self.unsupported_count = sum(i.status == CapabilityStatus.UNSUPPORTED for i in self.issues)
        self.manual_review_count = sum(i.status == CapabilityStatus.MANUAL_REVIEW for i in self.issues)
        self.generation_blocked = any(i.blocks_generation for i in self.issues)

    @property
    def requires_manual_review(self) -> bool:
        return self.partial_count > 0 or self.unsupported_count > 0 or self.manual_review_count > 0

    def __iter__(self):
        return iter(self.issues)

    def __len__(self) -> int:
        return len(self.issues)

    def __getitem__(self, index):
        return self.issues[index]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issues": [
                {
                    "feature": issue.feature,
                    "status": issue.status.value,
                    "reason": issue.reason,
                    "object_type": issue.object_type,
                    "object_id": issue.object_id,
                    "target_vendor": issue.target_vendor,
                    "blocks_generation": issue.blocks_generation,
                }
                for issue in self.issues
            ],
            "supported_count": self.supported_count,
            "partial_count": self.partial_count,
            "unsupported_count": self.unsupported_count,
            "manual_review_count": self.manual_review_count,
            "generation_blocked": self.generation_blocked,
        }

class FieldCapability(BaseModel):
    """
    Describes the support level and constraints of a specific configuration field.
    """
    support: FeatureSupport
    max_length: Optional[int] = None
    allowed_characters: Optional[str] = None
    max_items: Optional[int] = None # For lists
    notes: Optional[str] = None
    blocks_generation: bool = False

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
