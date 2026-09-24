from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPGatewayInterface(CheckPointSourceObject):
    ipv4_address: str | None = Field(default=None, alias="ipv4-address")
    ipv4_network_mask: str | None = Field(default=None, alias="ipv4-network-mask")
    ipv6_address: str | None = Field(default=None, alias="ipv6-address")
    zone: CheckPointObjectReference | str | None = None
    topology: str | None = None


class CPGateway(CheckPointSourceObject):
    gateway_type: str | None = None
    management_identity: str | None = None
    address: str | None = None
    interfaces: list[CPGatewayInterface] = Field(default_factory=list)
    topology: dict | None = None
    zone: CheckPointObjectReference | str | None = None
    vpn: dict | None = None
    nat_settings: dict | None = None


class CPCluster(CPGateway):
    members: list[CheckPointObjectReference | str] = Field(default_factory=list)
    cluster_mode: str | None = None


class CPInteroperableDevice(CPGateway):
    pass


__all__ = ["CPCluster", "CPGateway", "CPGatewayInterface", "CPInteroperableDevice"]
