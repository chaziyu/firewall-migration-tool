from typing import Dict, List, Optional

from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.cisco_ftd.extractor import extract_cisco_ftd_config
from fwmigrate.parsers.cisco_ftd.fmc_bundle import CiscoFMCBundleParser, is_fmc_bundle


class CiscoFTDSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "cisco_ftd"

    @property
    def display_name(self) -> str:
        return "Cisco Firepower Threat Defense"

    @property
    def supported_extensions(self) -> List[str]:
        return [".cfg", ".txt", ".conf", ".json"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        if is_fmc_bundle(content):
            return CiscoFMCBundleParser(content).parse()
        return CiscoFTDParser(content).parse()

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        return extract_cisco_ftd_config(content)


from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser

PluginRegistry.register_parser(CiscoFTDSourceParser)

__all__ = [
    "CiscoFTDSourceParser", "CiscoFTDParser", "CiscoFMCBundleParser",
    "extract_cisco_ftd_config", "is_fmc_bundle",
]
