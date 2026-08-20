from typing import List, Optional, Dict, Any
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.base_api_client import BaseAPIClient
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.api_client import FortiGateAPIClient
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

class FortiGateLiveAPIClient(BaseAPIClient):
    @classmethod
    def vendor_id_class(cls) -> str:
        return "fortigate"

    @property
    def vendor_id(self) -> str:
        return "fortigate"

    @property
    def display_name(self) -> str:
        return "Fortinet FortiGate REST API"

    @classmethod
    def get_field_definitions(cls) -> List[Dict[str, Any]]:
        return [
            {"name": "host", "label": "FortiGate IP / Hostname", "type": "text", "required": True, "placeholder": "192.168.1.99"},
            {"name": "port", "label": "HTTPS Port", "type": "number", "required": True, "default": 443},
            {"name": "api_key", "label": "REST API Token", "type": "password", "required": False, "placeholder": "Bearer token"},
            {"name": "username", "label": "Admin Username", "type": "text", "required": False, "placeholder": "admin"},
            {"name": "password", "label": "Admin Password", "type": "password", "required": False, "placeholder": "••••••••"},
            {"name": "vdom", "label": "VDOM Name", "type": "text", "required": False, "default": "root"},
            {"name": "verify_ssl", "label": "Verify SSL Certificate", "type": "checkbox", "default": False},
        ]

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.client = FortiGateAPIClient(
            host=kwargs.get("host", ""),
            port=int(kwargs.get("port", 443)),
            api_key=kwargs.get("api_key") or None,
            username=kwargs.get("username") or None,
            password=kwargs.get("password") or None,
            vdom=kwargs.get("vdom", "root"),
            verify_ssl=bool(kwargs.get("verify_ssl", False))
        )

    def validate_connection(self) -> bool:
        try:
            return bool(self.client.validate_connection())
        except Exception:
            return False

    def extract_config(self) -> IRConfig:
        fg_config = self.client.extract_config()
        zone_mapping = self.kwargs.get("zone_mapping", {})
        transformer = FGToIRTransformer(fg_config, zone_mapping=zone_mapping)
        return transformer.transform()

# Register automatically
PluginRegistry.register_parser(FortiGateSourceParser)
PluginRegistry.register_api_client(FortiGateLiveAPIClient)
