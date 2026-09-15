# Canonical IR common domain models

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class IRVirtualFirewallContext(BaseModel):
    context_id: Optional[str] = None
    context_type: Optional[str] = None
    parent_context: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    routing_instances: List[str] = Field(default_factory=list)
    administrators: List[str] = Field(default_factory=list)
    resource_limits: Dict[str, Any] = Field(default_factory=dict)
    mode: Optional[str] = None

    vdom: str = "root"
    scope: str = "vdom"
    central_nat: Optional[str] = None
    ngfw_mode: Optional[str] = None
    opmode: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_legacy_context_fields(self):
        if self.context_id is None:
            self.context_id = self.vdom
        elif self.vdom == "root":
            self.vdom = self.context_id
        if self.context_type is None:
            self.context_type = self.scope
        elif self.scope == "vdom":
            self.scope = self.context_type
        return self


IRExecutionContext = IRVirtualFirewallContext


__all__ = [
    "IRVirtualFirewallContext",
    "IRExecutionContext",
]
