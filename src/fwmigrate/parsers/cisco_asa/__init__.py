from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.api_client import CiscoFMCAPIClient

class CiscoASASourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "cisco_asa"

    @property
    def display_name(self) -> str:
        return "Cisco ASA / Firepower (FTD)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".cfg", ".txt", ".conf"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        parser = CiscoASAParser(content, zone_mapping=zone_mapping)
        return parser.transform_to_ir()

# Auto-register
PluginRegistry.register_parser(CiscoASASourceParser)
PluginRegistry.register_api_client(CiscoFMCAPIClient)

__all__ = ["CiscoASASourceParser", "CiscoFMCAPIClient"]
