from typing import Dict, List, Optional

from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.ir import IRConfig
from fwmigrate.parsers.cisco_ftd.extractor import extract_cisco_ftd_config
from fwmigrate.parsers.cisco_ftd.fmc_adapter import CiscoFMCBundleParser, is_fmc_bundle
from fwmigrate.parsers.cisco_ftd.fdm_adapter import CiscoFDMBundleParser, is_fdm_bundle


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
        if is_fdm_bundle(content):
            return CiscoFDMBundleParser(content).parse()
        return CiscoFTDParser(content).parse()

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        return extract_cisco_ftd_config(content)


from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser

__all__ = [
    "CiscoFTDSourceParser", "CiscoFTDParser", "CiscoFMCBundleParser", "CiscoFDMBundleParser",
    "extract_cisco_ftd_config", "is_fmc_bundle", "is_fdm_bundle",
]
