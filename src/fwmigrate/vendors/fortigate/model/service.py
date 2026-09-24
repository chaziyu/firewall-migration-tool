from typing import Any

from pydantic import BaseModel, Field

# config firewall service category
class FGServiceCategory(BaseModel):
    name: str
    vdom: str = "root"

    comment: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)

# config firewall service custom
class FGService(BaseModel):
    name: str
    vdom: str = "root"

    # Category reference
    category: str | None = None

    # Source protocol semantics
    protocol: str | None = None
    protocol_number: int | None = None

    # Port-based services
    tcp_portrange: str | None = None
    udp_portrange: str | None = None
    sctp_portrange: str | None = None

    # ICMP services
    icmptype: int | None = None
    icmpcode: int | None = None

    # Proxy service flag
    proxy: str | None = None

    # Description
    comment: str | None = None

    # Keep only if you actually want these in reports later
    session_ttl: int | str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)

# config firewall service group
class FGServiceGroup(BaseModel):
    name: str
    vdom: str = "root"

    members: list[str] = Field(default_factory=list)

    proxy: str | None = None
    comment: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)