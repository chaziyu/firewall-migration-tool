from typing import Any

from pydantic import BaseModel, Field


class FGIPPool(BaseModel):
    name: str
    vdom: str = "root"

    # Pool identity / range
    type: str | None = None
    startip: str | None = None
    endip: str | None = None

    # Optional source-address restriction
    source_startip: str | None = None
    source_endip: str | None = None

    # Port range, relevant to some pool types
    startport: int | None = None
    endport: int | None = None

    # Interface / ARP behavior
    associated_interface: str | None = None
    arp_reply: str | None = None
    arp_intf: str | None = None

    # NAT behavior
    permit_any_host: str | None = None
    nat64: str | None = None
    add_nat64_route: str | None = None

    # Explicit exclusions
    exclude_ip: list[str] = Field(default_factory=list)

    # Description
    comments: str | None = None

    # Preserve unsupported source settings
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)