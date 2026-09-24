from typing import Any, Literal

from pydantic import BaseModel, Field


class FGVIP6(BaseModel):
    name: str
    vdom: str = "root"
    address_family: Literal["ipv6"] = "ipv6"
    extip: str | None = None
    mappedip: str | None = None
    extport: str | None = None
    mappedport: str | None = None
    ipv4_mappedip: str | None = None
    ipv4_mappedport: str | None = None
    embedded_ipv4_address: str | None = None
    portforward: str | None = None
    protocol: str | None = None
    nat64: str | None = None
    nat66: str | None = None
    ndp_reply: str | None = None
    add_nat64_route: str | None = None
    nat_source_vip: str | None = None
    comment: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGVIPGroup6(BaseModel):
    name: str
    vdom: str = "root"
    address_family: Literal["ipv6"] = "ipv6"
    uuid: str | None = None
    color: int | None = None
    members: list[str] = Field(default_factory=list)
    comments: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
