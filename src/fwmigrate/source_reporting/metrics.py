"""Optional timing diagnostics for source-report requests."""

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class SourceReportStageMetric:
    stage: str
    duration_ms: float


@dataclass
class SourceReportMetrics:
    stages: list[SourceReportStageMetric] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    total_duration_ms: float = 0.0

    def add(self, stage: str, duration_ms: float) -> None:
        self.stages.append(SourceReportStageMetric(stage, duration_ms))

    def set_metadata(self, key: str, value: object) -> None:
        self.metadata[key] = value

    def as_dict(self) -> dict[str, object]:
        return {
            "total_duration_ms": self.total_duration_ms,
            "metadata": dict(self.metadata),
            "stages": [asdict(metric) for metric in self.stages],
        }


__all__ = ["SourceReportMetrics", "SourceReportStageMetric"]
