from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..source_model import PANScope

ResolutionStatus = Literal["RESOLVED", "UNRESOLVED", "AMBIGUOUS", "SOURCE_ONLY"]


@dataclass(frozen=True, slots=True)
class PANIndexedObject:
    family: str
    name: str
    scope: PANScope | None
    source_path: str


@dataclass(frozen=True, slots=True)
class PANReferenceResolution:
    status: ResolutionStatus
    owner_name: str | None
    owner_field: str
    reference_name: str
    expected_family: str
    source_scope: PANScope | None
    resolved_target_scope: PANScope | None = None
    target_source_path: str | None = None
    resolution_reason: str = ""


@dataclass(frozen=True, slots=True)
class PANShadowedObject:
    family: str
    name: str
    visible_from: str
    candidates: tuple[PANIndexedObject, ...]
    selection: str
