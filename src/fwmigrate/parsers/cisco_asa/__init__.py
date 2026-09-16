from typing import Dict, List, Optional
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.extraction import finalize_extraction

from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config


class CiscoASASourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "cisco_asa"

    @property
    def display_name(self) -> str:
        return "Cisco ASA"

    @property
    def supported_extensions(self) -> List[str]:
        return [".cfg", ".txt", ".conf"]

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        return finalize_extraction(
            extract_cisco_asa_config(content, zone_mapping=zone_mapping)
        )


__all__ = ["CiscoASASourceParser", "extract_cisco_asa_config"]
