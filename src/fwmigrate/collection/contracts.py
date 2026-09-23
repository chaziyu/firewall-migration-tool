"""Transport contracts for vendor-native live source collection."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class CollectionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


@dataclass(frozen=True)
class CollectionPart:
    name: str
    status: str
    complete: bool = True
    count: int | None = None


@dataclass(frozen=True)
class CollectedSource:
    vendor_id: str
    source_text: str
    source_name: str
    method: str
    status: CollectionStatus = CollectionStatus.SUCCESS
    metadata: dict[str, Any] = field(default_factory=dict)
    parts: tuple[CollectionPart, ...] = ()
    warnings: tuple[str, ...] = ()


class CollectionError(RuntimeError):
    """Safe error message suitable for a collection response."""


class SourceCollector(Protocol):
    vendor_id: str
    method: str
    fields: tuple[dict[str, Any], ...]

    def validate_options(self, connection: dict[str, Any]) -> dict[str, Any]: ...
    def test_connection(self, options: dict[str, Any]) -> None: ...
    def collect(self, options: dict[str, Any]) -> CollectedSource: ...


def validate_connection(connection: dict[str, Any], *, port: int, optional: tuple[str, ...] = ()) -> dict[str, Any]:
    if not isinstance(connection, dict):
        raise ValueError("Connection details are required.")
    options = {key: str(connection.get(key, "")).strip() for key in ("host", "username", "password", *optional)}
    try:
        options["port"] = int(connection.get("port", port))
    except (TypeError, ValueError) as exc:
        raise ValueError("Port must be between 1 and 65535.") from exc
    if not all(options[key] for key in ("host", "username", "password")) or not 1 <= options["port"] <= 65535:
        raise ValueError("Host, username, password, and a valid port are required.")
    if any(character in options["host"] for character in "/@?#\\"):
        raise ValueError("Host must be a hostname or IP address without a URL path.")
    return options


SSH_FIELDS = (
    {"name": "host", "label": "SSH host", "type": "text", "required": True},
    {"name": "port", "label": "SSH port", "type": "number", "required": True, "default": 22},
    {"name": "username", "label": "Username", "type": "text", "required": True},
    {"name": "password", "label": "Password", "type": "password", "required": True},
)
