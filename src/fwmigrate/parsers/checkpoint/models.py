"""Check Point R81 parser input and response models."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CheckPointResponse(BaseModel):
    """A single Check Point Management API command response or exported section."""
    model_config = ConfigDict(populate_by_name=True)

    command: str
    data: Dict[str, Any] = Field(default_factory=dict)
    domain: Optional[str] = None
    package: Optional[str] = None
    layer: Optional[str] = None
    gateway: Optional[str] = None
    from_index: Optional[int] = Field(default=None, alias="from")
    to_index: Optional[int] = Field(default=None, alias="to")
    total: Optional[int] = None


class ScopeSelectionResult(BaseModel):
    """Diagnostic outcome of domain, package, access layer, and gateway scope resolution."""
    selected_domain: Optional[str] = None
    selected_package: Optional[str] = None
    selected_access_layer: Optional[str] = None
    selected_access_layer_uid: Optional[str] = None
    selected_gateway: Optional[str] = None
    ambiguous: bool = False
    reasons: List[str] = Field(default_factory=list)


class CheckPointExportBundle(BaseModel):
    """Container for multi-command offline Check Point JSON export bundles."""
    model_config = ConfigDict(populate_by_name=True)

    format: str = "checkpoint-export-v1"
    api_version: Optional[str] = None
    management_server: Optional[str] = None
    domain: Optional[str] = None
    gateway: Optional[str] = None
    selected_domain: Optional[str] = None
    selected_package: Optional[str] = None
    selected_access_layer: Optional[str] = None
    selected_access_layer_uid: Optional[str] = None
    selected_gateway: Optional[str] = None
    responses: List[CheckPointResponse] = Field(default_factory=list)
    gaia_responses: List[Dict[str, Any]] = Field(default_factory=list)
