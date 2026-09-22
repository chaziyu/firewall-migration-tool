from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANStaticRoute(BaseModel):
    name: str | None = None
    source_path: str = ""
    scope: PANScope | None = None
    source_order: int | None = None
    destination: str | None = None
    nexthop_ip_address: str | None = None
    interface: str | None = None
    metric: str | None = None
    nexthop: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANBGPPeer(BaseModel):
    name: str | None = None
    enable: str | None = None
    peer_as: str | None = None
    peer_address: str | None = None
    local_interface: str | None = None
    local_ip: str | None = None
    bfd_profile: str | None = None
    hold_time: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANBGPPeerGroup(BaseModel):
    name: str | None = None
    enable: str | None = None
    auth_profile: str | None = None
    peers: list[PANBGPPeer] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANBGPConfig(BaseModel):
    enable: str | None = None
    router_id: str | None = None
    local_as: str | None = None
    bfd_profile: str | None = None
    redistribution_rules: list[str] | None = None
    peer_groups: list[PANBGPPeerGroup] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANOSPFInterface(BaseModel):
    name: str | None = None
    metric: str | None = None
    cost: str | None = None
    priority: str | None = None
    passive: str | None = None
    link_type: str | None = None
    bfd_profile: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANOSPFArea(BaseModel):
    name: str | None = None
    interfaces: list[PANOSPFInterface] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANOSPFConfig(BaseModel):
    enable: str | None = None
    router_id: str | None = None
    areas: list[PANOSPFArea] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANOSPFv3Config(PANOSPFConfig):
    pass


class PANRIPConfig(BaseModel):
    enable: str | None = None
    interfaces: list[PANOSPFInterface] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANRedistributionProfile(BaseModel):
    name: str | None = None
    priority: str | None = None
    action: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANVirtualRouter(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    interfaces: list[str] | None = None
    static_routes: list[PANStaticRoute] | None = None
    bgp: PANBGPConfig | None = None
    ospf: PANOSPFConfig | None = None
    ospfv3: PANOSPFv3Config | None = None
    rip: PANRIPConfig | None = None
    redistribution_profiles: list[PANRedistributionProfile] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANVRF(BaseModel):
    name: str | None = None
    routing_protocol: dict[str, Any] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANLogicalRouter(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    vrfs: list[PANVRF] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
