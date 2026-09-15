from typing import List, Optional, Dict

from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.extraction import ExtractionResult, finalize_extraction
from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


class CheckPointSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "checkpoint"

    @property
    def display_name(self) -> str:
        return "Check Point R80/R81 (JSON Dump / API)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".json", ".txt", ".cfg"]

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        return finalize_extraction(
            extract_checkpoint_config(content, zone_mapping=zone_mapping)
        )


