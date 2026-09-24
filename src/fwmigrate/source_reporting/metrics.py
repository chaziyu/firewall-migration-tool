"""Optional timing diagnostics for source-report requests."""

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class SourceReportStageMetric:
    stage: str
    duration_ms: float


@dataclass
class SourceReportMetrics:
    stages: list[SourceReportStageMetric] = field(default_factory=list)
    total_duration_ms: float = 0.0

    def add(self, stage: str, duration_ms: float) -> None:
        self.stages.append(SourceReportStageMetric(stage, duration_ms))

    def as_dict(self) -> dict[str, object]:
        return {
            "total_duration_ms": self.total_duration_ms,
            "stages": [asdict(metric) for metric in self.stages],
        }


__all__ = ["SourceReportMetrics", "SourceReportStageMetric"]
