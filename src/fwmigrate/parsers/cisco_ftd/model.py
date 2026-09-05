from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CiscoFTDManagementSetting(BaseModel):
    name: str
    setting: str
    values: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True


class CiscoFTDConfig(BaseModel):
    source_vendor: str = "cisco_ftd"
    source_product: str = "Cisco Firepower Threat Defense"
    version: Optional[str] = None
    cmi_enabled: Optional[bool] = None
    management_ipv4: Optional[str] = None
    management_netmask: Optional[str] = None
    management_gateway: Optional[str] = None
    management_dns_servers: List[str] = Field(default_factory=list)
    ssh_access_list: List[str] = Field(default_factory=list)
    diagnostic_interface: Optional[str] = None
    management_settings: List[CiscoFTDManagementSetting] = Field(default_factory=list)
