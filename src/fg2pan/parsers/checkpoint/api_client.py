import requests
import urllib3
from typing import List, Dict, Any, Optional
from fg2pan.core.base_api_client import BaseAPIClient
from fg2pan.ir.core import IRConfig, IRMetadata, IRZone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CheckPointAPIClient(BaseAPIClient):
    """API Client for Check Point Web Management API (/web_api/)."""

    @classmethod
    def vendor_id_class(cls) -> str:
        return "checkpoint"

    @property
    def vendor_id(self) -> str:
        return "checkpoint"

    @property
    def display_name(self) -> str:
        return "Check Point R80/R81 Management API"

    @classmethod
    def get_field_definitions(cls) -> List[Dict[str, Any]]:
        return [
            {"name": "host", "label": "Management Server IP / Hostname", "type": "text", "required": True, "placeholder": "192.168.1.10"},
            {"name": "port", "label": "HTTPS Port", "type": "number", "required": True, "default": 443},
            {"name": "username", "label": "Admin Username", "type": "text", "required": True, "placeholder": "admin"},
            {"name": "password", "label": "Admin Password", "type": "password", "required": True, "placeholder": "••••••••"},
            {"name": "domain", "label": "Domain (MDS / Multi-Domain)", "type": "text", "required": False, "placeholder": "Default"},
            {"name": "verify_ssl", "label": "Verify SSL Certificate", "type": "checkbox", "default": False},
        ]

    def __init__(self, **kwargs):
        self.host = kwargs.get("host", "").strip().rstrip('/')
        self.port = int(kwargs.get("port", 443))
        self.username = kwargs.get("username", "")
        self.password = kwargs.get("password", "")
        self.domain = kwargs.get("domain") or None
        self.verify_ssl = bool(kwargs.get("verify_ssl", False))
        self.base_url = f"https://{self.host}:{self.port}/web_api"
        self.sid = None

    def validate_connection(self) -> bool:
        if not self.host or not self.username:
            return False
        try:
            payload = {"user": self.username, "password": self.password}
            if self.domain:
                payload["domain"] = self.domain
            resp = requests.post(f"{self.base_url}/login", json=payload, verify=self.verify_ssl, timeout=5)
            if resp.status_code == 200 and 'sid' in resp.json():
                self.sid = resp.json()['sid']
                return True
            return False
        except Exception:
            return False

    def extract_config(self) -> IRConfig:
        ir = IRConfig(metadata=IRMetadata(hostname=self.host, source_vendor="checkpoint"))
        ir.zones.append(IRZone(name="trust", interfaces=["eth0"]))
        ir.zones.append(IRZone(name="untrust", interfaces=["eth1"]))
        return ir
