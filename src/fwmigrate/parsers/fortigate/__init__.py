from typing import List, Optional, Dict, Any
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.shaping_models import install_phase22_parser_support


# Install focused Phase 22 typed source handling after the base parser module
# has loaded. This changes extraction fidelity only; target generators remain
# untouched.
install_phase22_parser_support()


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

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        return self.extract(content, zone_mapping=zone_mapping).canonical_ir

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        return extract_fortigate_config(content, zone_mapping=zone_mapping)


# Register automatically
PluginRegistry.register_parser(FortiGateSourceParser)
