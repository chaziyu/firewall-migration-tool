from typing import List, Optional, Dict
from fg2pan.core.base_parser import BaseSourceParser
from fg2pan.core.registry import PluginRegistry
from fg2pan.ir.core import IRConfig
from fg2pan.parsers.checkpoint.parser import CheckPointParser
from fg2pan.parsers.checkpoint.api_client import CheckPointAPIClient

class CheckPointSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "checkpoint"

    @property
    def display_name(self) -> str:
        return "Check Point R80/R81 (JSON Dump / API)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".json", ".txt"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        parser = CheckPointParser(content, zone_mapping=zone_mapping)
        return parser.parse()

# Auto-register
PluginRegistry.register_parser(CheckPointSourceParser)
PluginRegistry.register_api_client(CheckPointAPIClient)

__all__ = ["CheckPointSourceParser", "CheckPointAPIClient"]
