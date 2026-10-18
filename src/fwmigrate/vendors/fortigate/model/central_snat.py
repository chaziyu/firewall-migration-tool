"""Explicit FortiOS 7.4.6 central SNAT source rules."""

from typing import Any

from pydantic import BaseModel, Field


class FGCentralSNAT(BaseModel):
    policy_id: int | None = None
    vdom: str | None = None
    srcintf: list[str] | None = None
    dstintf: list[str] | None = None
    orig_addr: list[str] | None = None
    orig_addr6: list[str] | None = None
    dst_addr: list[str] | None = None
    dst_addr6: list[str] | None = None
    nat_ippool: list[str] | None = None
    nat_ippool6: list[str] | None = None
    protocol: int | None = None
    orig_port: str | None = None
    dst_port: str | None = None
    nat_port: str | None = None
    port_preserve: str | None = None
    nat: str | None = None
    nat46: str | None = None
    nat64: str | None = None
    status: str | None = None
    type: str | None = None
    uuid: str | None = None
    comments: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
