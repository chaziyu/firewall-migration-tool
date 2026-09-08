"""Extraction metadata is a reporting companion, never target configuration."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ExtractionStatus(str, Enum):
    NORMALIZED = "NORMALIZED"
    PARTIALLY_NORMALIZED = "PARTIALLY_NORMALIZED"
    EXTRACT_ONLY = "EXTRACT_ONLY"
    VENDOR_EXTENSION = "VENDOR_EXTENSION"
    UNSUPPORTED = "UNSUPPORTED"
    IGNORED_BY_POLICY = "IGNORED_BY_POLICY"
    PARSE_ERROR = "PARSE_ERROR"


class SourceObjectResult(BaseModel):
    id: str
    section: str
    name: str
    scope: str = "root"
    sequence: int = 0
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    api_path: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    status: ExtractionStatus = ExtractionStatus.EXTRACT_ONLY
    parsed: bool = True
    canonical_ids: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    blocking: bool = False


class SourceSectionResult(BaseModel):
    path: str
    scope: str = "root"
    present: bool = True
    source_count: Optional[int] = 0
    notes: List[str] = Field(default_factory=list)


class ExtractionReport(BaseModel):
    schema_version: str = "1.0"
    # Coverage is explicitly limited; do not infer whole-file completeness.
    coverage_scope: str = "NAT sections and firewall-policy NAT linkage only"
    objects: List[SourceObjectResult] = Field(default_factory=list)
    sections: List[SourceSectionResult] = Field(default_factory=list)
    diagnostics: List[str] = Field(default_factory=list)
    blocking_issues: List[str] = Field(default_factory=list)

    @property
    def status(self) -> str:
        if self.blocking_issues or any(o.blocking or not o.parsed for o in self.objects):
            return "PARTIAL"
        if self.diagnostics or any(o.status != ExtractionStatus.NORMALIZED for o in self.objects):
            return "COMPLETE_WITH_WARNINGS"
        return "COMPLETE"

    def assert_migration_ready(self) -> None:
        if self.blocking_issues or any(o.blocking for o in self.objects):
            raise ValueError("NAT extraction requires manual review. Download the source Excel inventory and resolve its NAT diagnostics before migration.")
