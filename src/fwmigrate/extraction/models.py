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

    # Optional additive coverage fields.  Existing vendor extractors continue
    # to use ``path`` and the original counters.
    coverage_section: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    object_count_total: Optional[int] = None
    object_count_partial: int = 0
    object_count_extract_only: int = 0
    object_count_unsupported: int = 0
    object_count_parse_error: int = 0
    supported_empty: bool = False
    collection_errors: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_commands: List[str] = Field(default_factory=list)
    operational: bool = False

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
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
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
    evidence_class: str = "configuration"

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


class CoverageSummary(BaseModel):
    """Deterministic support summary for one extraction coverage section."""

    section: str
    domain: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    scope: str = "domain"
    operational: bool = False
    status: ExtractionStatus
    total: int = 0
    normalized: int = 0
    partial: int = 0
    extract_only: int = 0
    unsupported: int = 0
    parse_errors: int = 0
    supported_empty: bool = False
    collection_errors: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_commands: List[str] = Field(default_factory=list)


class UnsupportedItem(BaseModel):
    source_path: str
    source_name: Optional[str] = None
    reason: str
    requires_manual_review: bool = True
    raw_capture: Optional[str] = None


class ExtractionResult(BaseModel):
    canonical_ir: IRConfig

    source_sections: List[SourceSectionResult] = Field(default_factory=list)
    coverage: List[CoverageSummary] = Field(default_factory=list)
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

