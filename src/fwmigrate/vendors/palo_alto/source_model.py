from dataclasses import dataclass, field
import xml.etree.ElementTree as ET
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List, Literal


@dataclass(frozen=True)
class PANSourceDocument:
    """Parsed PAN-OS XML input retained for source extraction."""

    root: ET.Element
    raw_content: str
    hostname: Optional[str] = None
    source_version: Optional[str] = None

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
    template_stack: Optional[str] = None
    template_provenance: Dict[str, Any] = Field(default_factory=dict)

class PANSourceRecord(BaseModel):
    """A source-faithful PAN-OS XML record.

    This is deliberately close to PAN-OS XML.  It is not a portable firewall
    object and carries no vendor defaults or target-generation state.
    """

    kind: str
    source_path: str
    name: Optional[str] = None
    scope: Optional[PANScope] = None
    rulebase_position: Literal["pre", "local", "post"] | None = None
    values: Dict[str, Any] = Field(default_factory=dict)
    source_order: Optional[int] = None
    raw_xml: Optional[str] = None
    unsupported: bool = False


class PANOSConfig(BaseModel):
    """Vendor-native PAN-OS source configuration."""

    hostname: Optional[str] = None
    source_version: Optional[str] = None
    source_format: str = "xml"
    scopes: List[PANScope] = Field(default_factory=list)
    records: List[PANSourceRecord] = Field(default_factory=list)
    unknown_paths: List[str] = Field(default_factory=list)

    def records_of(self, *kinds: str) -> list[PANSourceRecord]:
        wanted = set(kinds)
        return [record for record in self.records if record.kind in wanted]


@dataclass(frozen=True)
class PANOSDerivedViews:
    """Read-only views over PAN-OS source state."""

    counts: Dict[str, int] = field(default_factory=dict)
    scope_identities: tuple[str, ...] = ()
    unresolved_references: tuple[str, ...] = ()


@dataclass(frozen=True)
class PANOSValidationIssue:
    severity: str
    domain: str
    message: str
    source_path: Optional[str] = None
    source_name: Optional[str] = None


@dataclass(frozen=True)
class PANOSValidationResult:
    issues: tuple[PANOSValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[PANOSValidationIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "error")


def pan_scope_identity(scope: PANScope) -> str:
    """Return a stable identity for explicit source ownership context."""
    identity = f"{scope.kind}:{scope.name}"
    if scope.kind == "shared":
        return identity

    qualifier = scope.device_serial or scope.device_name
    if qualifier:
        identity += f":device:{qualifier}"
    return identity
