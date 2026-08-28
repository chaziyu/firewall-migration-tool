from typing import List, Optional, Dict, Any
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer

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
        fg_config = parse_fortigate_config(content)
        transformer = FGToIRTransformer(fg_config, zone_mapping=zone_mapping or {})
        return transformer.transform()


# Register automatically
PluginRegistry.register_parser(FortiGateSourceParser)
