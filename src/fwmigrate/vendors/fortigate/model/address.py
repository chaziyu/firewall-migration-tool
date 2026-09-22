from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class FGAddressTaggingEntry(BaseModel):
    name: str
    category: str | None = None
    tags: list[str] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddress(BaseModel):
    name: str
    vdom: str = "root"

    address_family: Literal["ipv4", "ipv6"] = "ipv4"

    type: str | None = None

    subnet: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None
    fqdn: str | None = None
    wildcard: str | None = None
    wildcard_fqdn: str | None = None

    associated_interface: str | None = None
    allow_routing: str | None = None
    comment: str | None = None

    tagging: list[FGAddressTaggingEntry] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGWildcardFQDN(BaseModel):
    name: str
    vdom: str = "root"

    wildcard_fqdn: str | None = None
    comment: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddressGroupTaggingEntry(BaseModel):
    name: str
    category: str | None = None
    tags: list[str] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAddressGroup(BaseModel):
    name: str
    vdom: str = "root"

    address_family: Literal["ipv4", "ipv6"] = "ipv4"

    members: list[str] = Field(default_factory=list)

    exclude: str | None = None
    exclude_members: list[str] = Field(default_factory=list)

    comment: str | None = None

    type: str | None = None
    category: str | None = None
    allow_routing: str | None = None

    tagging: list[FGAddressGroupTaggingEntry] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
