from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.ir.core import IRConfig


class ExtractionStatus(str, Enum):
    NORMALIZED = "NORMALIZED"
    PARTIALLY_NORMALIZED = "PARTIALLY_NORMALIZED"
    EXTRACT_ONLY = "EXTRACT_ONLY"
    VENDOR_EXTENSION = "VENDOR_EXTENSION"
    UNSUPPORTED = "UNSUPPORTED"
    IGNORED_BY_POLICY = "IGNORED_BY_POLICY"
    PARSE_ERROR = "PARSE_ERROR"


class SourceSectionResult(BaseModel):
    path: str
    present: bool = True

    line_start: Optional[int] = None
    line_end: Optional[int] = None

    object_count_source: Optional[int] = None
    object_count_parsed: Optional[int] = None
    object_count_normalized: Optional[int] = None

    status: ExtractionStatus

    parser_handler: Optional[str] = None
    notes: List[str] = Field(default_factory=list)


class SourceCommand(BaseModel):
    operation: str
    key: str
    values: List[str] = Field(default_factory=list)


class SourceInventoryItem(BaseModel):
    domain: str
    source_path: str

    name: Optional[str] = None
    source_id: Optional[str] = None
    source_record_id: Optional[str] = None
    source_type: Optional[str] = None

    commands: List[SourceCommand] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    source_references: List[str] = Field(default_factory=list)
    children: List["SourceInventoryItem"] = Field(default_factory=list)

    status: ExtractionStatus = ExtractionStatus.EXTRACT_ONLY
    requires_manual_review: bool = False

    notes: List[str] = Field(default_factory=list)


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

