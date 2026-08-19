from pydantic import BaseModel
from typing import Dict, Optional

class MigrationConfig(BaseModel):
    zone_mapping: Dict[str, str] = {}
    target_format: str = "xml"
    target_version: str = "11.1.0"
    
    @classmethod
    def from_yaml(cls, filepath: str) -> "MigrationConfig":
        import yaml
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**(data or {}))
