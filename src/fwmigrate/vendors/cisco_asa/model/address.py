from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import Field
from .base import CiscoSourceModel


class CiscoNetworkObject(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    type: Optional[str] = None
    value: Optional[str] = None
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    nat_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    address_family: Optional[str] = None


class CiscoNetworkGroupMember(CiscoSourceModel):
    type: str
    value: str
    address_family: Optional[str] = None
    raw: str = ""
    review_reasons: List[str] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Keep the old dictionary access working for parser consumers."""
        return getattr(self, key)


class CiscoNetworkGroup(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    address_family: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[CiscoNetworkGroupMember] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
