from pydantic import BaseModel, Field
from typing import Dict


class MigrationConfig(BaseModel):
    zone_mapping: Dict[str, str] = Field(default_factory=dict)
    context_mapping: Dict[str, str] = Field(default_factory=dict)
    target_format: str = "xml"
    target_version: str = "11.1.0"

    @classmethod
    def from_yaml(cls, filepath: str) -> "MigrationConfig":
        import yaml
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**(data or {}))
