"""Vendor-native juniper_srx common models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand


class JuniperContextType(str, Enum):
    ROOT = "root"
    LOGICAL_SYSTEM = "logical-system"
    TENANT = "tenant"


@dataclass(frozen=True)
class JuniperConfigContext:
    context_type: JuniperContextType
    name: Optional[str] = None

    @property
    def key(self) -> tuple[JuniperContextType, Optional[str]]:
        return self.context_type, self.name

    @property
    def storage_key(self) -> str:
        return "root" if self.context_type is JuniperContextType.ROOT else f"{self.context_type.value}:{self.name}"


class JuniperProvenanceKind(str, Enum):
    LOCAL = "LOCAL"
    INHERITED_GROUP = "INHERITED_GROUP"
    PREDEFINED_SHARED = "PREDEFINED_SHARED"


@dataclass(frozen=True)
class JuniperSourceProvenance:
    kind: JuniperProvenanceKind = JuniperProvenanceKind.LOCAL
    context: Optional[JuniperConfigContext] = None
    group_name: Optional[str] = None
    source_path: Optional[tuple[str, ...]] = None


@dataclass(frozen=True)
class JuniperEffectiveProvenance:
    provenance_kind: JuniperProvenanceKind = JuniperProvenanceKind.LOCAL
    source_context: Optional[JuniperConfigContext] = None
    source_group_name: Optional[str] = None
    source_group_chain: tuple[str, ...] = ()
    source_path: Optional[tuple[str, ...]] = None
    target_context: Optional[JuniperConfigContext] = None
    target_path: Optional[tuple[str, ...]] = None
    hierarchy_depth: int = 0
    group_priority: int = 0
    group_list_priority: int = 0
    group_application_depth: int = 0
    recursion_depth: int = 0
    group_recursion_depth: int = 0
    source_order: int = 0
    overridden: bool = False
    excluded: bool = False
    inactive: bool = False


class JuniperResolutionStatus(str, Enum):
    EFFECTIVE = "EFFECTIVE"
    SHADOWED = "SHADOWED"
    EXCLUDED = "EXCLUDED"
    INACTIVE = "INACTIVE"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNRESOLVED = "UNRESOLVED"


class JuniperGroupApplication(BaseModel):
    target_context: Optional[JuniperConfigContext] = None
    target_path: tuple[str, ...] = ()
    ordered_groups: List[str] = Field(default_factory=list)
    excluded_groups: List[str] = Field(default_factory=list)
    source_order: int = 0
    group_list_priority: int = 0
    group_application_depth: int = 0
    hierarchy_depth: int = 0
    active: bool = True
    source_metadata: Dict[str, Any] = Field(default_factory=dict)


class JuniperEffectiveCandidate(BaseModel):
    value: Any = None
    target_path: tuple[str, ...] = ()
    field_key: str
    provenance: Optional[JuniperEffectiveProvenance] = None
    status: JuniperResolutionStatus = JuniperResolutionStatus.EFFECTIVE
    effective: bool = True
    shadowed: bool = False
    excluded: bool = False
    inactive: bool = False
    reason: Optional[str] = None
    group_list_priority: int = 0
    group_application_depth: int = 0
    group_recursion_depth: int = 0
    hierarchy_depth: int = 0
    source_order: int = 0


class JuniperEffectiveModel(BaseModel):
    """Common history contract for structured, group-inheritable models."""
    field_provenance: Dict[str, JuniperEffectiveProvenance] = Field(default_factory=dict)
    field_candidate_history: Dict[str, List[JuniperEffectiveCandidate]] = Field(default_factory=dict)
    member_candidate_history: Dict[str, List[JuniperEffectiveCandidate]] = Field(default_factory=dict)


class JuniperGroupStatement(BaseModel):
    hierarchy_path: tuple[str, ...] = ()
    leaf_keyword: str
    leaf_values: List[str] = Field(default_factory=list)
    active: bool = True
    source_order: int = 0
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    referenced_group_name: Optional[str] = None
    source_group_name: Optional[str] = None
    source_path: Optional[tuple[str, ...]] = None


class JuniperGroupNode(BaseModel):
    path_component: str
    wildcard: bool = False
    children: Dict[str, "JuniperGroupNode"] = Field(default_factory=dict)
    statements: List[JuniperGroupStatement] = Field(default_factory=list)
    apply_groups: List[str] = Field(default_factory=list)
    apply_groups_except: List[str] = Field(default_factory=list)
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    apply_group_provenance: List[Dict[str, Any]] = Field(default_factory=list)
    applications: List["JuniperGroupApplication"] = Field(default_factory=list)


class JuniperConfigurationGroup(BaseModel):
    name: str
    root_node: JuniperGroupNode
    context_type: str = "root"
    context_name: Optional[str] = None
    source_metadata: Dict[str, Any] = Field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.root_node.children or self.root_node.statements)


class JuniperSourceHierarchyItem(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
