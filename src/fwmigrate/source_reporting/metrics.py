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
    details: dict[str, object] = field(default_factory=dict)

    def add(self, stage: str, duration_ms: float) -> None:
        self.stages.append(SourceReportStageMetric(stage, duration_ms))

    def set_metadata(self, key: str, value: object) -> None:
        self.metadata[key] = value

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "total_duration_ms": self.total_duration_ms,
            "metadata": dict(self.metadata),
            "stages": [asdict(metric) for metric in self.stages],
        }
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class ExcelExportMetrics:
    """FAST Excel timings and sheet dimensions; deliberately excludes cell values."""

    stages: dict[str, float] = field(default_factory=dict)
    sheets: list[dict[str, int | float | str]] = field(default_factory=list)

    def add_stage(self, stage: str, duration_ms: float) -> None:
        self.stages[stage] = duration_ms

    def add_sheet(self, name: str, row_count: int, column_count: int, duration_ms: float) -> None:
        self.sheets.append({
            "sheet_name": name,
            "row_count": row_count,
            "column_count": column_count,
            "duration_ms": duration_ms,
        })

    def as_dict(self) -> dict[str, object]:
        return {"stages": dict(self.stages), "sheets": [dict(sheet) for sheet in self.sheets]}


__all__ = ["ExcelExportMetrics", "SourceReportMetrics", "SourceReportStageMetric"]
