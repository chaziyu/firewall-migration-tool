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


class CPGaiaStaticRoute(CheckPointSourceObject):
    address_family: str | None = None
    ipv4_destination: str | None = None
    ipv6_destination: str | None = None
    next_hop: str | None = None
    outgoing_interface: str | None = None
    enabled: bool | None = None


class CPGaiaDHCPPool(CheckPointSourceObject):
    start: str | None = None
    end: str | None = None
    enabled: bool | None = None
    state: str | None = None


class CPGaiaDHCPSubnet(CheckPointSourceObject):
    subnet: str | None = None
    prefix: int | None = None
    enabled: bool | None = None
    included_pools: list[CPGaiaDHCPPool] = Field(default_factory=list)
    excluded_pools: list[CPGaiaDHCPPool] = Field(default_factory=list)
    lease: str | int | None = None
    gateway: str | None = None
    domain: str | None = None
    dns_servers: list[str] = Field(default_factory=list)


class CPGaiaDHCPServer(CheckPointSourceObject):
    process_state: str | None = None
    enabled: bool | None = None
    subnets: list[CPGaiaDHCPSubnet] = Field(default_factory=list)


class CPGaiaUser(CheckPointSourceObject):
    authentication_method: str | None = None
    shell: str | None = None
    roles: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPGaiaRBARole(CheckPointSourceObject):
    permissions: list[str] = Field(default_factory=list)


class CPGaiaRBAUserAssignment(CheckPointSourceObject):
    user: CheckPointObjectReference | str | None = None
    roles: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPVTI(CheckPointSourceObject):
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
    "CPGaiaDHCPPool", "CPGaiaDHCPServer", "CPGaiaDHCPSubnet", "CPGaiaInterface",
    "CPGaiaRBAUserAssignment", "CPGaiaRBARole", "CPGaiaStaticRoute", "CPGaiaUser",
    "CPVTI", "GaiaConfiguration", "GaiaInterface", "GaiaRoute", "GaiaSourceObject",
]
