"""Check Point source-owned models built from collection envelopes."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .models import CollectionStatus


class CheckPointSourceRecord(BaseModel):
    """One source object, rule, or configuration record."""
    model_config = ConfigDict(extra="allow")
    uid: Optional[str] = None
    name: Optional[str] = None
    object_type: Optional[str] = None
    source_plane: str = "management"
    command: str
    domain: Optional[str] = None
    domain_uid: Optional[str] = None
    package: Optional[str] = None
    package_uid: Optional[str] = None
    layer: Optional[str] = None
    layer_uid: Optional[str] = None
    parent_layer_uid: Optional[str] = None
    gateway: Optional[str] = None
    order: Optional[int] = None
    members: List[Any] = Field(default_factory=list)
    references: List[Any] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CheckPointCollectionDiagnostic(BaseModel):
    command: str
    source_plane: str
    domain: Optional[str] = None
    package: Optional[str] = None
    layer: Optional[str] = None
    gateway: Optional[str] = None
    status: CollectionStatus
    complete: bool = False
    error: Optional[str] = None
    error_code: Optional[str] = None
    from_index: Optional[int] = None
    to_index: Optional[int] = None
    total: Optional[int] = None


class CheckPointConfig(BaseModel):
    """Check Point-native source aggregate; never an IR projection."""
    model_config = ConfigDict(extra="allow")
    api_version: Optional[str] = None
    management_server: Optional[str] = None
    domains: List[CheckPointSourceRecord] = Field(default_factory=list)
    packages: List[CheckPointSourceRecord] = Field(default_factory=list)
    access_layers: List[CheckPointSourceRecord] = Field(default_factory=list)
    network_objects: List[CheckPointSourceRecord] = Field(default_factory=list)
    groups: List[CheckPointSourceRecord] = Field(default_factory=list)
    services: List[CheckPointSourceRecord] = Field(default_factory=list)
    applications: List[CheckPointSourceRecord] = Field(default_factory=list)
    schedules: List[CheckPointSourceRecord] = Field(default_factory=list)
    access_rules: List[CheckPointSourceRecord] = Field(default_factory=list)
    nat_rules: List[CheckPointSourceRecord] = Field(default_factory=list)
    vpn_communities: List[CheckPointSourceRecord] = Field(default_factory=list)
    gateways: List[CheckPointSourceRecord] = Field(default_factory=list)
    identity_objects: List[CheckPointSourceRecord] = Field(default_factory=list)
    threat_prevention: List[CheckPointSourceRecord] = Field(default_factory=list)
    https_inspection: List[CheckPointSourceRecord] = Field(default_factory=list)
    gaia_interfaces: List[CheckPointSourceRecord] = Field(default_factory=list)
    gaia_routes: List[CheckPointSourceRecord] = Field(default_factory=list)
    pbr: List[CheckPointSourceRecord] = Field(default_factory=list)
    dns_ntp: List[CheckPointSourceRecord] = Field(default_factory=list)
    cluster_state: List[CheckPointSourceRecord] = Field(default_factory=list)
    management_access: List[CheckPointSourceRecord] = Field(default_factory=list)
    collection: List[CheckPointCollectionDiagnostic] = Field(default_factory=list)


__all__ = ["CheckPointCollectionDiagnostic", "CheckPointConfig", "CheckPointSourceRecord"]
