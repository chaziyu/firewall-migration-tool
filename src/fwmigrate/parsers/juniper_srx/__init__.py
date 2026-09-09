from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

class JuniperSRXSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "juniper_srx"

    @property
    def display_name(self) -> str:
        return "Juniper SRX (Junos root-level display set)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".set", ".txt", ".conf"]

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        """One authoritative extraction pipeline returning complete ExtractionResult."""
        parser = JuniperSRXParser(content, zone_mapping=zone_mapping)
        return parser.extract()

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        """Compatibility projection returning canonical IRConfig."""
        return self.extract(content, zone_mapping=zone_mapping).canonical_ir

# Auto-register
PluginRegistry.register_parser(JuniperSRXSourceParser)

__all__ = ["JuniperSRXSourceParser"]
