from typing import Any, Literal

from pydantic import BaseModel, Field

class FGVIPRealServer(BaseModel):
    """Real server used by load-balancing/server-load-balance VIPs."""

    id: int | None = None

    ip: str | None = None
    address: str | None = None
    port: int | None = None

    status: str | None = None
    weight: int | None = None

    monitor: list[str] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)

class FGVIP(BaseModel):
    name: str
    vdom: str = "root"
    address_family: Literal["ipv4"] = "ipv4"

    # Identity / state
    uuid: str | None = None
    status: str | None = None

    # VIP behavior
    type: str | None = None

    # External/public side
    extip: str | None = None
    extaddr: list[str] = Field(default_factory=list)
    extintf: str | None = None

    # Internal/mapped side
    mappedip: list[str] = Field(default_factory=list)
    mapped_addr: str | None = None

    # Port forwarding
    portforward: str | None = None
    protocol: str | None = None
    extport: str | None = None
    mappedport: str | None = None

    # NAT / ARP behavior
    arp_reply: str | None = None
    nat_source_vip: str | None = None

    # Service-based VIP
    service: list[str] = Field(default_factory=list)

    # Load balancing
    ldb_method: str | None = None
    server_type: str | None = None
    monitor: list[str] = Field(default_factory=list)
    realservers: list[FGVIPRealServer] = Field(default_factory=list)

    # Description
    comment: str | None = None

    # Preserve unsupported explicit FortiOS settings
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGVIPGroup(BaseModel):
    name: str
    vdom: str = "root"
    address_family: Literal["ipv4"] = "ipv4"

    uuid: str | None = None

    interface: str | None = None
    members: list[str] = Field(default_factory=list)

    comments: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
