from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPService(CheckPointSourceObject):
    port: str | int | None = None
    protocol: str | int | None = None
    source_port: str | int | None = None
    icmp_type: int | str | None = None
    icmp_code: int | str | None = None
    ip_protocol: int | str | None = None
    match: str | None = None
    session_timeout: int | None = None
    members: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPServiceGroup(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] = Field(default_factory=list)


__all__ = ["CPService", "CPServiceGroup"]
