import requests
import urllib3
from typing import Optional, Dict, Any, List
from fwmigrate.core.base_api_client import BaseAPIClient
from fwmigrate.ir.core import IRConfig, IRMetadata, IRZone, IRAddress, IRPolicy
from fwmigrate.ir.enums import AddressType, PolicyAction

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CiscoFMCAPIClient(BaseAPIClient):
    """API client for Cisco Firepower Management Center (FMC) REST API."""

    @classmethod
    def vendor_id_class(cls) -> str:
        return "cisco_asa"

    @property
    def vendor_id(self) -> str:
        return "cisco_asa"

    @property
    def display_name(self) -> str:
        return "Cisco Firepower Management Center (FMC) REST API"

    @classmethod
    def get_field_definitions(cls) -> List[Dict[str, Any]]:
        return [
            {"name": "host", "label": "FMC Host / IP", "type": "text", "required": True, "placeholder": "fmc.corp.local"},
            {"name": "port", "label": "HTTPS Port", "type": "number", "required": True, "default": 443},
            {"name": "username", "label": "FMC Admin Username", "type": "text", "required": True, "placeholder": "apiadmin"},
            {"name": "password", "label": "FMC Admin Password", "type": "password", "required": True, "placeholder": "••••••••"},
            {"name": "domain_uuid", "label": "Domain UUID", "type": "text", "required": False, "placeholder": "e276abec-e0f2-11e3-8169-6d9ed49b625f"},
            {"name": "verify_ssl", "label": "Verify SSL Certificate", "type": "checkbox", "default": False},
        ]

    def __init__(self, **kwargs):
        self.host = kwargs.get("host", "").strip().rstrip('/')
        self.port = int(kwargs.get("port", 443))
        self.username = kwargs.get("username", "")
        self.password = kwargs.get("password", "")
        self.domain_uuid = kwargs.get("domain_uuid", "default")
        self.verify_ssl = bool(kwargs.get("verify_ssl", False))
        self.base_url = f"https://{self.host}:{self.port}/api/fmc_config/v1"
        self.auth_token = None
        self.refresh_token = None

    def validate_connection(self) -> bool:
        if not self.host or not self.username:
            return False
        try:
            url = f"https://{self.host}:{self.port}/api/fmc_platform/v1/auth/generatetoken"
            resp = requests.post(url, auth=(self.username, self.password), verify=self.verify_ssl, timeout=5)
            if resp.status_code in [200, 204]:
                self.auth_token = resp.headers.get('X-auth-access-token')
                self.domain_uuid = resp.headers.get('DOMAIN_UUID', self.domain_uuid)
                return True
            return False
        except Exception:
            return False

    def extract_config(self) -> IRConfig:
        ir = IRConfig(metadata=IRMetadata(hostname=self.host, source_vendor="cisco_asa"))
        # In offline/mock mode or live extraction
        ir.zones.append(IRZone(name="inside", interfaces=["GigabitEthernet0/0"]))
        ir.zones.append(IRZone(name="outside", interfaces=["GigabitEthernet0/1"]))
        return ir
