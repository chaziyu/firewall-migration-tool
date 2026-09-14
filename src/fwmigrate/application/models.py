from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.application.safety import SafetyDecision, SafetyIssue


@dataclass
class MigrationRequest:
    source_vendor: str
    target_vendor: str
    source_content: str
    target_format: str = "all"
    optimize: bool = False
    prune_unused: bool = False
    source_name: Optional[str] = None
    zone_mapping: Dict[str, str] = field(default_factory=dict)
    target_options: Dict[str, str] = field(default_factory=dict)


@dataclass
class MigrationResult:
    extraction: ExtractionResult
    source_ir: Optional[IRConfig]
    final_ir: Optional[IRConfig]
    artifacts: List[MigrationArtifact] = field(default_factory=list)
    target_display_name: Optional[str] = None
    unused_objects: Dict[str, List[str]] = field(default_factory=dict)
    generation_allowed: bool = True
    blocking_reasons: List[str] = field(default_factory=list)
    requires_manual_review: bool = False
    warnings: List[str] = field(default_factory=list)
    safety_decisions: List[SafetyDecision] = field(default_factory=list)
    safety_issues: List[SafetyIssue] = field(default_factory=list)
    validation_issues: List[object] = field(default_factory=list)
    capability_issues: List[object] = field(default_factory=list)
