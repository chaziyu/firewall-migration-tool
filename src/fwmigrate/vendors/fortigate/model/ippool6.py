from typing import Any, Literal

from pydantic import BaseModel, Field


class FGIPPool6(BaseModel):
    name: str
    vdom: str = "root"
    address_family: Literal["ipv6"] = "ipv6"
    add_nat46_route: str | None = None
    comments: str | None = None
    endip: str | None = None
    nat46: str | None = None
    startip: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
