from typing import Any

from pydantic import BaseModel, Field


class FGSecurityPolicy(BaseModel):
    policy_id: int | None = None
    vdom: str | None = "root"
    action: str | None = None
    app_category: list[int] | None = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGProtocolOptionsProfile(BaseModel):
    name: str
    vdom: str | None = "root"
    comment: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGPerIPShaper(BaseModel):
    name: str
    vdom: str | None = "root"
    max_bandwidth: int | None = None
    bandwidth_unit: str | None = None
    max_concurrent_session: int | None = None
    max_concurrent_tcp_session: int | None = None
    max_concurrent_udp_session: int | None = None
    diffserv_forward: str | None = None
    diffserv_reverse: str | None = None
    diffservcode_forward: str | None = None
    diffservcode_rev: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
