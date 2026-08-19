from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.api_client import JuniperPyEZClient

class JuniperSRXSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "juniper_srx"

    @property
    def display_name(self) -> str:
        return "Juniper SRX (JunOS 'set' syntax)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".set", ".txt", ".conf"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        parser = JuniperSRXParser(content, zone_mapping=zone_mapping)
        return parser.transform_to_ir()

# Auto-register
PluginRegistry.register_parser(JuniperSRXSourceParser)
PluginRegistry.register_api_client(JuniperPyEZClient)

__all__ = ["JuniperSRXSourceParser", "JuniperPyEZClient"]
