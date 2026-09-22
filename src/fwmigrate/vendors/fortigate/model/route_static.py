from typing import Any, Literal

from pydantic import BaseModel, Field


class FGStaticRoute(BaseModel):
    # Identity / context
    seq_num: int | None = None
    vdom: str = "root"
    address_family: Literal["ipv4", "ipv6"] = "ipv4"

    # Destination
    dst: str | None = None
    dstaddr: str | None = None

    # Forwarding path
    device: str | None = None
    gateway: str | None = None
    dynamic_gateway: str | None = None

    # Special forwarding behavior
    blackhole: str | None = None

    # Route preference
    distance: int | None = None
    priority: int | None = None

    # Routing context
    vrf: int | None = None
    sdwan_zone: list[str] = Field(default_factory=list)

    # Optional source-specific routing
    src: str | None = None
    preferred_source: str | None = None

    # State / metadata
    status: str | None = None
    comment: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)