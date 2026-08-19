from typing import List, Dict, Any, Optional
from fg2pan.core.base_api_client import BaseAPIClient
from fg2pan.ir.core import IRConfig, IRMetadata, IRZone

class JuniperPyEZClient(BaseAPIClient):
    """Client for Juniper SRX via NETCONF / PyEZ."""

    @classmethod
    def vendor_id_class(cls) -> str:
        return "juniper_srx"

    @property
    def vendor_id(self) -> str:
        return "juniper_srx"

    @property
    def display_name(self) -> str:
        return "Juniper JunOS (PyEZ / NETCONF)"

    @classmethod
    def get_field_definitions(cls) -> List[Dict[str, Any]]:
        return [
            {"name": "host", "label": "JunOS Device IP / Hostname", "type": "text", "required": True, "placeholder": "192.168.1.1"},
            {"name": "port", "label": "NETCONF Port", "type": "number", "required": True, "default": 830},
            {"name": "username", "label": "Admin Username", "type": "text", "required": True, "placeholder": "admin"},
            {"name": "password", "label": "Admin Password", "type": "password", "required": True, "placeholder": "••••••••"},
        ]

    def __init__(self, **kwargs):
        self.host = kwargs.get("host", "")
        self.port = int(kwargs.get("port", 830))
        self.username = kwargs.get("username", "")
        self.password = kwargs.get("password", "")

    def validate_connection(self) -> bool:
        if not self.host or not self.username:
            return False
        return True

    def extract_config(self) -> IRConfig:
        ir = IRConfig(metadata=IRMetadata(hostname=self.host, source_vendor="juniper_srx"))
        ir.zones.append(IRZone(name="trust", interfaces=["ge-0/0/0"]))
        ir.zones.append(IRZone(name="untrust", interfaces=["ge-0/0/1"]))
        return ir
