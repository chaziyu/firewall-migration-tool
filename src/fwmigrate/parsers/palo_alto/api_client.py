import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from fwmigrate.core.base_api_client import BaseAPIClient
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser

class PANOSLiveAPIClient(BaseAPIClient):
    """Palo Alto Networks PAN-OS XML / REST API client for live extraction."""

    @classmethod
    def vendor_id_class(cls) -> str:
        return "palo_alto"

    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks XML API"

    @classmethod
    def get_field_definitions(cls) -> List[Dict[str, Any]]:
        return [
            {"name": "host", "label": "PAN-OS IP / Hostname", "type": "text", "required": True, "placeholder": "192.168.1.1"},
            {"name": "port", "label": "HTTPS Port", "type": "number", "required": True, "default": 443},
            {"name": "api_key", "label": "PAN-OS API Key", "type": "password", "required": False, "placeholder": "LUFRPT..."},
            {"name": "username", "label": "Admin Username", "type": "text", "required": False, "placeholder": "admin"},
            {"name": "password", "label": "Admin Password", "type": "password", "required": False, "placeholder": "••••••••"},
            {"name": "vsys", "label": "Virtual System", "type": "text", "required": False, "default": "vsys1"},
            {"name": "verify_ssl", "label": "Verify SSL Certificate", "type": "checkbox", "default": False},
        ]

    def __init__(self, **kwargs):
        self.host = kwargs.get("host", "").strip()
        self.port = int(kwargs.get("port", 443))
        self.api_key = kwargs.get("api_key") or None
        self.username = kwargs.get("username") or None
        self.password = kwargs.get("password") or None
        self.vsys = kwargs.get("vsys", "vsys1")
        self.verify_ssl = bool(kwargs.get("verify_ssl", False))
        self.base_url = f"https://{self.host}:{self.port}/api"

    def _ensure_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        if self.username and self.password:
            url = f"{self.base_url}/?type=keygen&user={self.username}&password={self.password}"
            resp = requests.get(url, verify=self.verify_ssl, timeout=10)
            if resp.status_code == 200:
                root = ET.fromstring(resp.content)
                key_elem = root.find(".//key")
                if key_elem is not None and key_elem.text:
                    self.api_key = key_elem.text.strip()
                    return self.api_key
            raise RuntimeError("Failed to generate PAN-OS API key from username and password.")
        raise RuntimeError("Neither API key nor username/password was provided for PAN-OS.")

    def validate_connection(self) -> bool:
        try:
            key = self._ensure_api_key()
            url = f"{self.base_url}/?type=op&cmd=<show><system><info></info></show>&key={key}"
            resp = requests.get(url, verify=self.verify_ssl, timeout=10)
            return resp.status_code == 200 and b"status=\"success\"" in resp.content
        except Exception:
            return False

    def extract_config(self) -> IRConfig:
        key = self._ensure_api_key()
        # Retrieve running configuration
        url = f"{self.base_url}/?type=config&action=show&key={key}"
        resp = requests.get(url, verify=self.verify_ssl, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch PAN-OS configuration (HTTP {resp.status_code}): {resp.text}")

        parser = PANOSSourceParser()
        return parser.parse(resp.text)
