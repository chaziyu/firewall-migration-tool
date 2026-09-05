"""Check Point R81 parser input and response models."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CollectionStatus(str, Enum):
    """Outcome of one source command without conflating empty data and failure."""

    SUCCESS_WITH_DATA = "SUCCESS_WITH_DATA"
    SUCCESS_EMPTY = "SUCCESS_EMPTY"
    UNSUPPORTED_COMMAND = "UNSUPPORTED_COMMAND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    API_ERROR = "API_ERROR"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    # Backward-compatible values used by historical/offline bundles.
    OK = "OK"
    ERROR = "ERROR"


SUCCESS_COLLECTION_STATUSES = {
    CollectionStatus.SUCCESS_WITH_DATA,
    CollectionStatus.SUCCESS_EMPTY,
    CollectionStatus.OK,
}


def collection_status_is_success(status: CollectionStatus | str) -> bool:
    """Return whether a command result can be consumed as collected source data."""
    try:
        return CollectionStatus(status) in SUCCESS_COLLECTION_STATUSES
    except ValueError:
        return False


class CollectionCompletenessRecord(BaseModel):
    """Explicit command/family completeness for one source scope."""

    command: str
    domain: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    domain_type: Optional[str] = None
    package: Optional[str] = None
    package_uid: Optional[str] = None
    layer: Optional[str] = None
    layer_uid: Optional[str] = None
    gateway: Optional[str] = None
    status: CollectionStatus
    complete: bool
    object_count: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class CheckPointResponse(BaseModel):
    """A single Check Point Management API command response or exported section."""
    model_config = ConfigDict(populate_by_name=True)

    command: str
    data: Dict[str, Any] = Field(default_factory=dict)
    domain: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    domain_type: Optional[str] = None
    package: Optional[str] = None
    package_uid: Optional[str] = None
    layer: Optional[str] = None
    layer_uid: Optional[str] = None
    parent_layer: Optional[str] = None
    parent_layer_uid: Optional[str] = None
    parent_rule_uid: Optional[str] = None
    gateway: Optional[str] = None
    source_response: Optional[str] = None
    cluster_member: Optional[str] = None
    from_index: Optional[int] = Field(default=None, alias="from")
    to_index: Optional[int] = Field(default=None, alias="to")
    total: Optional[int] = None
    collection_status: CollectionStatus = CollectionStatus.OK
    collection_error_code: Optional[str] = None
    object_count: Optional[int] = None
    collection_warnings: List[str] = Field(default_factory=list)
    error: Optional[str] = None

    def domain_identity(self) -> Optional[str]:
        return self.domain_uid or self.domain_name or self.domain

    def domain_scope_key(self) -> str:
        return self.domain_identity() or "global"


class ScopeSelectionResult(BaseModel):
    """Diagnostic outcome of domain, package, access layer, and gateway scope resolution."""
    selected_domain: Optional[str] = None
    selected_package: Optional[str] = None
    selected_access_layer: Optional[str] = None
    selected_access_layer_uid: Optional[str] = None
    selected_gateway: Optional[str] = None
    ambiguous: bool = False
    reasons: List[str] = Field(default_factory=list)


class RulebaseSafetyState(BaseModel):
    """Pre-transformation safety state for one grouped API rulebase."""

    complete: bool = True
    reasons: List[str] = Field(default_factory=list)


class CheckPointExportBundle(BaseModel):
    """Container for multi-command offline Check Point JSON export bundles."""
    model_config = ConfigDict(populate_by_name=True)

    format: str = "checkpoint-export-v1"
    api_version: Optional[str] = None
    management_server: Optional[str] = None
    domain: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    gateway: Optional[str] = None
    selected_domain: Optional[str] = None
    selected_domain_uid: Optional[str] = None
    selected_package: Optional[str] = None
    selected_access_layer: Optional[str] = None
    selected_access_layer_uid: Optional[str] = None
    selected_gateway: Optional[str] = None
    collection_scope: Optional[str] = None
    collection_completeness: Dict[str, CollectionCompletenessRecord] = Field(default_factory=dict)
    responses: List[CheckPointResponse] = Field(default_factory=list)
    gaia_responses: List[Dict[str, Any]] = Field(default_factory=list)
