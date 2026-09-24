from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPGaiaInterface(CheckPointSourceObject):
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    mask_length: int | None = None
    state: str | None = None
    zone: CheckPointObjectReference | str | None = None
    topology: str | None = None


class CPGaiaRouteNextHop(CheckPointSourceObject):
    next_hop_type: str | None = None
    gateway: str | None = None
    interface: str | None = None
    priority: str | int | None = None
    ping: bool | None = None
    ping6: bool | None = None
    rank: str | int | None = None
    scopelocal: bool | None = None
    blackhole: bool | None = None
    reject: bool | None = None


class CPGaiaStaticRoute(CheckPointSourceObject):
    address_family: str | None = None
    ipv4_destination: str | None = None
    ipv6_destination: str | None = None
    next_hops: list[CPGaiaRouteNextHop] = Field(default_factory=list)
    enabled: bool | None = None
    comment: str | None = None
    rank: str | int | None = None
    scopelocal: bool | None = None
    default: bool | None = None


class CPGaiaDHCPPool(CheckPointSourceObject):
    start: str | None = None
    end: str | None = None
    enabled: bool | None = None
    state: str | None = None


class CPGaiaDHCPSubnet(CheckPointSourceObject):
    subnet: str | None = None
    netmask: str | None = None
    prefix: int | None = None
    enabled: bool | None = None
    included_pools: list[CPGaiaDHCPPool] = Field(default_factory=list)
    excluded_pools: list[CPGaiaDHCPPool] = Field(default_factory=list)
    lease: str | int | None = None
    default_lease: str | int | None = None
    maximum_lease: str | int | None = Field(default=None, alias="max-lease")
    gateway: str | None = None
    domain: str | None = None
    dns_servers: list[str] = Field(default_factory=list)


class CPGaiaDHCPServer(CheckPointSourceObject):
    process_state: str | None = None
    enabled: bool | None = None
    subnets: list[CPGaiaDHCPSubnet] = Field(default_factory=list)


class CPGaiaUser(CheckPointSourceObject):
    uid: int | str | None = None
    gid: int | str | None = None
    home: str | None = None
    real_name: str | None = None
    lock_out: bool | None = None
    force_password_change: bool | None = None
    authentication_method: str | None = None
    shell: str | None = None
    roles: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPGaiaRBARole(CheckPointSourceObject):
    domain_type: str | None = None
    all_features: bool | None = None
    read_only_features: list[str] = Field(default_factory=list)
    read_write_features: list[str] = Field(default_factory=list)
    virtual_system_access: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


class CPGaiaRBAUserAssignment(CheckPointSourceObject):
    user: CheckPointObjectReference | str | None = None
    roles: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPVTI(CheckPointSourceObject):
    tunnel_id: int | str | None = None
    tunnel_type: str | None = None
    local_address: str | None = None
    remote_address: str | None = None
    local_device: str | None = None
    interface: str | None = None
    peer: CheckPointObjectReference | str | None = None
    address: str | None = None
    state: str | None = None


# Existing names remain import-compatible for the current Gaia reporting code.
GaiaSourceObject = CheckPointSourceObject
GaiaInterface = CPGaiaInterface
GaiaRoute = CPGaiaStaticRoute
GaiaConfiguration = CheckPointSourceObject

__all__ = [
    "CPGaiaDHCPPool", "CPGaiaDHCPServer", "CPGaiaDHCPSubnet", "CPGaiaInterface", "CPGaiaRouteNextHop",
    "CPGaiaRBAUserAssignment", "CPGaiaRBARole", "CPGaiaStaticRoute", "CPGaiaUser",
    "CPVTI", "GaiaConfiguration", "GaiaInterface", "GaiaRoute", "GaiaSourceObject",
]
