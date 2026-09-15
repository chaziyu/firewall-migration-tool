from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.core.normalizer import NormalizationResult
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir import IRConfig
from fwmigrate.capabilities.schema import CapabilityAnalysisResult
from fwmigrate.application.metrics import PipelineMetrics


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
    collect_metrics: bool = False


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
    normalization: Optional[NormalizationResult] = None
    capability_analysis: Optional[CapabilityAnalysisResult] = None
    metrics: Optional[PipelineMetrics] = None
