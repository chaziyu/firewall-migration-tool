from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.ir.core import IRConfig


class ExtractionStatus(str, Enum):
    NORMALIZED = "NORMALIZED"
    PARTIALLY_NORMALIZED = "PARTIALLY_NORMALIZED"
    EXTRACT_ONLY = "EXTRACT_ONLY"
    # Compatibility alias for the conservative unknown-section fallback.  It
    # intentionally retains the historical serialized value so existing
    # clients that only understand UNSUPPORTED remain safe.
    EXTRACT_ONLY_UNKNOWN = "UNSUPPORTED"
    VENDOR_EXTENSION = "VENDOR_EXTENSION"
    UNSUPPORTED = "UNSUPPORTED"
    IGNORED_BY_POLICY = "IGNORED_BY_POLICY"
    PARSE_ERROR = "PARSE_ERROR"


class SourceSectionResult(BaseModel):
    path: str
    source_context: Optional[str] = None
    present: bool = True

    line_start: Optional[int] = None
    line_end: Optional[int] = None

    object_count_source: Optional[int] = None
    object_count_parsed: Optional[int] = None
    object_count_normalized: Optional[int] = None

    # Counted independently from object cardinality.  Matching source and
    # parsed object counts is not proof that every semantic setting was
    # normalized.
    semantic_unknowns: List[str] = Field(default_factory=list)
    unresolved_dependencies: int = 0

    status: ExtractionStatus

    parser_handler: Optional[str] = None
    notes: List[str] = Field(default_factory=list)


class SourceCommand(BaseModel):
    operation: str
    key: str
    values: List[str] = Field(default_factory=list)
    line_number: Optional[int] = None
    status: Optional[ExtractionStatus] = None
    parser_handler: Optional[str] = None
    requires_manual_review: bool = False


class SourceInventoryItem(BaseModel):
    domain: str
    source_path: str

    name: Optional[str] = None
    source_id: Optional[str] = None
    source_record_id: Optional[str] = None
    source_type: Optional[str] = None
    source_context: Optional[str] = None

    commands: List[SourceCommand] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    source_references: List[str] = Field(default_factory=list)
    children: List["SourceInventoryItem"] = Field(default_factory=list)

    status: ExtractionStatus = ExtractionStatus.EXTRACT_ONLY
    requires_manual_review: bool = False

    notes: List[str] = Field(default_factory=list)


class DependencyRecord(BaseModel):
    """Context-scoped FortiGate reference resolution result."""

    source_context: Optional[str] = None
    source_path: str
    source_object: Optional[str] = None
    source_field: str
    reference: str
    expected_type: str
    result: str
    target_path: Optional[str] = None
    notes: Optional[str] = None


class UnsupportedItem(BaseModel):
    source_path: str
    source_name: Optional[str] = None
    reason: str
    requires_manual_review: bool = True
    raw_capture: Optional[str] = None


class ExtractionResult(BaseModel):
    canonical_ir: IRConfig

    source_sections: List[SourceSectionResult] = Field(default_factory=list)
    inventory_items: List[SourceInventoryItem] = Field(default_factory=list)
    unsupported_items: List[UnsupportedItem] = Field(default_factory=list)
    dependencies: List[DependencyRecord] = Field(default_factory=list)

    # Derived migration safety state. These additive fields intentionally keep
    # the existing ExtractionResult API and serialized shape backward
    # compatible for consumers that ignore unknown/new fields.
    requires_manual_review: bool = False
    migration_complete: bool = True
    generation_safe: bool = True
    blocking_reasons: List[str] = Field(default_factory=list)

