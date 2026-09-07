from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.phase10_17 import apply_phase_10_17_patches

# Install the additive ASA Phase 10-17 grammar/model extensions before the
# extractor imports and uses CiscoASAParser. The public parser API is unchanged.
apply_phase_10_17_patches(CiscoASAParser)

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

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        parser = CiscoASAParser(content, zone_mapping=zone_mapping)
        return parser.transform_to_ir()

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        return extract_cisco_asa_config(content, zone_mapping=zone_mapping)


# Auto-register
PluginRegistry.register_parser(CiscoASASourceParser)

__all__ = ["CiscoASASourceParser", "extract_cisco_asa_config"]
