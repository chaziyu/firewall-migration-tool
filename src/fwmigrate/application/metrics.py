from dataclasses import asdict, dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class PipelineStageMetric:
    stage: str
    duration_ms: float


@dataclass
class PipelineMetrics:
    """Opt-in timing data for one migration request."""

    stages: List[PipelineStageMetric] = field(default_factory=list)
    total_duration_ms: float = 0.0

    def add(self, stage: str, duration_ms: float) -> None:
        self.stages.append(PipelineStageMetric(stage, duration_ms))

    def as_dict(self) -> Dict[str, object]:
        return {
            "total_duration_ms": self.total_duration_ms,
            "stages": [asdict(metric) for metric in self.stages],
        }


__all__ = ["PipelineMetrics", "PipelineStageMetric"]
