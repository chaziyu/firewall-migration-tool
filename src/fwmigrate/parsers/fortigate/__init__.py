from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.extraction import ExtractionResult, finalize_extraction
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.section_registry import initialize_builtin_sections


initialize_builtin_sections()


class FortiGateSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "fortigate"

    @property
    def display_name(self) -> str:
        return "Fortinet FortiGate"

    @property
    def supported_extensions(self) -> List[str]:
        return [".conf", ".cfg", ".txt"]

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        return finalize_extraction(
            extract_fortigate_config(content, zone_mapping=zone_mapping)
        )

