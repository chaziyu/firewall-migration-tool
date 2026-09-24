from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPAddress(CheckPointSourceObject):
    nat_settings: dict | None = None
    ip_address: str | None = None
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    network: str | None = None
    subnet4: str | None = None
    mask_length4: int | None = None
    subnet6: str | None = None
    mask_length6: int | None = None
    ipv4_address_first: str | None = Field(default=None, alias="ipv4-address-first")
    ipv4_address_last: str | None = Field(default=None, alias="ipv4-address-last")
    fqdn: str | None = None


class CPHost(CPAddress):
    pass


class CPNetwork(CPAddress):
    pass


class CPAddressRange(CPAddress):
    pass


class CPDNSDomain(CPAddress):
    domain_name: str | None = None


class CPWildcardAddress(CPAddress):
    wildcard: str | None = None


class CPDynamicAddress(CPAddress):
    dynamic: str | None = None


class CPUpdatableObject(CPAddress):
    update_source: str | None = None


class CPGroup(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPGroupWithExclusion(CheckPointSourceObject):
    include: CheckPointObjectReference | str | None = None
    except_: CheckPointObjectReference | str | None = Field(default=None, alias="except")


CPAddressGroup = CPGroup

__all__ = [
    "CPAddress", "CPAddressGroup", "CPAddressRange", "CPDNSDomain", "CPDynamicAddress",
    "CPGroup", "CPGroupWithExclusion", "CPHost", "CPNetwork", "CPUpdatableObject",
    "CPWildcardAddress",
]
