from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANInterfaceIPv6Address(BaseModel):
    address: str | None = None
    enable: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANInterfaceUnit(BaseModel):
    name: str | None = None
    parent: str | None = None
    tag: str | None = None
    ipv4_addresses: list[str] | None = None
    ipv6_addresses: list[PANInterfaceIPv6Address] | None = None
    management_profile: str | None = None
    sdwan_enabled: str | None = None
    ipv6_sdwan_enabled: str | None = None
    sdwan_interface_profile: str | None = None
    upstream_nat: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANInterface(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None

    interface_family: str | None = None
    mode: str | list[str] | None = None

    comment: str | None = None
    link_state: str | None = None
    speed: str | None = None
    duplex: str | None = None
    management_profile: str | None = None
    mtu: str | None = None
    ipv4_addresses: list[str] | None = None
    ipv6_addresses: list[PANInterfaceIPv6Address] | None = None
    vlan: str | None = None
    lldp_enable: str | None = None
    sdwan_enabled: str | None = None
    ipv6_sdwan_enabled: str | None = None
    sdwan_interface_profile: str | None = None
    upstream_nat: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANInterfaceImport(BaseModel):
    scope: PANScope | None = None
    interfaces: list[str] | None = None
    virtual_routers: list[str] | None = None
    source_path: str
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
