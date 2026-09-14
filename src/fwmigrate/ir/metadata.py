# Canonical IR metadata domain models

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fwmigrate.ir.enums import MigrationConfidence


class IRMetadata(BaseModel):
    hostname: Optional[str] = None
    source_vendor: str = "fortinet"
    source_product: Optional[str] = None
    target_vendor: Optional[str] = None
    input_type: str = "Unknown"
    source_version: Optional[str] = None
    source_context: Optional[str] = None
    migration_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
class IRCheckpointManagementAccess(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    service: Optional[str] = None
    enabled: Optional[bool] = None
    port: Optional[int] = None
    interface: Optional[str] = None
    management_interface: Optional[str] = None
    web_enabled: Optional[bool] = None
    web_ssl_port: Optional[int] = None
    web_session_timeout: Optional[int] = None
    allowed_clients: List[Dict[str, Any]] = Field(default_factory=list)
    ssh_enabled: Optional[bool] = None
    ssh_port: Optional[int] = None
    local_admin: List[str] = Field(default_factory=list)
    permitted_clients: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    authorization: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointPerformanceSettings(BaseModel):
    name: str
    feature: str
    source_command: Optional[str] = None
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    instance_count: Optional[int] = None
    instance_count_explicit: Optional[bool] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointSecureXLSettings(IRCheckpointPerformanceSettings):
    feature: str = "securexl"
class IRCheckpointCoreXLSettings(IRCheckpointPerformanceSettings):
    feature: str = "corexl"
class IRAuditEntry(BaseModel):
    id: str
    category: str
    message: str
    confidence: MigrationConfidence
    original_config: Optional[str] = None


__all__ = [
    "IRMetadata",
    "IRCheckpointManagementAccess",
    "IRCheckpointPerformanceSettings",
    "IRCheckpointSecureXLSettings",
    "IRCheckpointCoreXLSettings",
    "IRAuditEntry",
]
