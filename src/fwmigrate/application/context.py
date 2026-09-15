from dataclasses import dataclass
from typing import Optional

from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.application.models import MigrationRequest
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir import IRConfig
from fwmigrate.ir.dependency import DependencyGraph
from fwmigrate.ir.index import IRIndex
from fwmigrate.validation.models import ValidationResult


@dataclass
class MigrationContext:
    """Runtime-only state shared by pipeline stages."""

    request: MigrationRequest
    extraction: Optional[ExtractionResult] = None
    ir: Optional[IRConfig] = None
    ir_index: Optional[IRIndex] = None
    dependency_graph: Optional[DependencyGraph] = None
    metrics: Optional[PipelineMetrics] = None
    validation_result: Optional[ValidationResult] = None

    def set_ir(self, ir: Optional[IRConfig]) -> None:
        self.ir = ir
        self.rebuild_index()

    def rebuild_index(self) -> None:
        """Rebuild all IR-derived state after an IR replacement."""
        self.ir_index = IRIndex.build(self.ir) if self.ir is not None else None
        self.dependency_graph = DependencyGraph(self.ir) if self.ir is not None else None


__all__ = ["MigrationContext"]
