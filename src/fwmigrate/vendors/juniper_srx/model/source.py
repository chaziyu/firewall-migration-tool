"""Vendor-native juniper_srx source models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .administration import JuniperAdminUser, JuniperDNSNameServer, JuniperLoginClass, JuniperNETCONFSettings, JuniperNTPSettings, JuniperPKISettings, JuniperSNMPSettings, JuniperSSHSettings, JuniperSyslogSettings, JuniperWebManagementSettings
from .common import JuniperConfigContext, JuniperConfigurationGroup, JuniperContextType, JuniperEffectiveCandidate, JuniperEffectiveProvenance, JuniperSourceHierarchyItem
from .context import JuniperContextConfig


class JuniperActivationDirective(BaseModel):
    operation: str
    hierarchy_path: tuple[str, ...]
    context_type: str = "root"
    context_name: Optional[str] = None
    source_order: int = 0
    line_number: int = 0


class JuniperSRXConfig(BaseModel):
    hostname: Optional[str] = None
    version: Optional[str] = None
    time_zone: Optional[str] = None
    name_servers: List[JuniperDNSNameServer] = Field(default_factory=list)
    domain_name: Optional[str] = None
    domain_search: List[str] = Field(default_factory=list)
    login_classes: Dict[str, JuniperLoginClass] = Field(default_factory=dict)
    admin_users: Dict[str, JuniperAdminUser] = Field(default_factory=dict)
    radius_servers: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    tacplus_servers: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    authentication_order: List[str] = Field(default_factory=list)
    ntp: JuniperNTPSettings = Field(default_factory=JuniperNTPSettings)
    ssh: JuniperSSHSettings = Field(default_factory=JuniperSSHSettings)
    netconf: JuniperNETCONFSettings = Field(default_factory=JuniperNETCONFSettings)
    web_management: JuniperWebManagementSettings = Field(default_factory=JuniperWebManagementSettings)
    snmp: JuniperSNMPSettings = Field(default_factory=JuniperSNMPSettings)
    syslog: JuniperSyslogSettings = Field(default_factory=JuniperSyslogSettings)
    pki: JuniperPKISettings = Field(default_factory=JuniperPKISettings)
    services: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    contexts: Dict[str, JuniperContextConfig] = Field(default_factory=dict)
    activation_directives: List[JuniperActivationDirective] = Field(default_factory=list)
    unsupported_commands: List[JunosCommand] = Field(default_factory=list)
    configuration_groups: Dict[str, JuniperConfigurationGroup] = Field(default_factory=dict)
    applied_groups: Dict[str, List[str]] = Field(default_factory=dict)
    applied_group_exceptions: Dict[str, List[str]] = Field(default_factory=dict)
    field_provenance: Dict[str, JuniperEffectiveProvenance] = Field(default_factory=dict)
    field_candidate_history: Dict[str, List[JuniperEffectiveCandidate]] = Field(default_factory=dict)

    @staticmethod
    def context_storage_key(name: str = "root", context_type: str = "root") -> str:
        kind = JuniperContextType(context_type)
        return JuniperConfigContext(kind, None if kind is JuniperContextType.ROOT else name).storage_key

    def iter_contexts(self):
        return self.contexts.values()

    def get_context(self, name: str = "root", context_type: str = "root") -> JuniperContextConfig:
        key = self.context_storage_key(name, context_type)
        context = self.contexts.get(key)
        if context is None:
            context = self.contexts[key] = JuniperContextConfig(name=name, context_type=context_type)
        return context

    def group_storage_key(self, name: str, context_type: str = "root", context_name: Optional[str] = None) -> str:
        scope = self.context_storage_key(context_name or "root", context_type)
        return name if scope == "root" else f"{scope}:{name}"
