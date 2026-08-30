from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class PANScope(BaseModel):
    kind: str
    name: str
    device_name: Optional[str] = None
    # A managed firewall serial is part of VSYS identity.  ``device_name`` is
    # retained for compatibility with standalone/device scopes, while this
    # field prevents two different firewalls' ``vsys1`` scopes from colliding.
    device_serial: Optional[str] = None
    vsys: Optional[str] = None
    device_group: Optional[str] = None
    parent_device_group: Optional[str] = None
    rulebase_position: Optional[str] = None

class PANSourceObject(BaseModel):
    domain: str
    kind: str
    source_path: str
    name: Optional[str] = None
    scope: Optional[PANScope] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    sanitized_excerpt: Optional[str] = None
    canonical_name: Optional[str] = None
    ir_object: Optional[Any] = None


def pan_scope_identity(scope: PANScope) -> str:
    """Return a stable, device-qualified source scope identity."""
    identity = f"{scope.kind}:{scope.name}"
    if scope.device_serial:
        identity += f":device:{scope.device_serial}"
    return identity
