from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ExtractionConfig(BaseModel):
    """
    Runtime configuration for FortiGate extraction and report export.

    This is intentionally vendor-extraction focused.
    It does not contain migration or target-vendor settings.
    """

    # Input handling
    encoding: str = "utf-8"

    # Extraction behavior
    preserve_unknown_sections: bool = True
    preserve_unknown_fields: bool = True
    include_source_metadata: bool = True

    # Validation behavior
    validate_references: bool = True
    validate_required_fields: bool = True

    # Export behavior
    output_format: str = "xlsx"
    include_validation_sheet: bool = True
    include_raw_extra: bool = False
    include_explicit_fields: bool = True

    # Optional sheet selection.
    # Empty means export every supported domain.
    enabled_sheets: list[str] = Field(default_factory=list)

    @classmethod
    def from_yaml(
        cls,
        filepath: str | Path,
    ) -> "ExtractionConfig":
        path = Path(filepath)

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)

        return cls.model_validate(data or {})