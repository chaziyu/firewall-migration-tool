from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPVPNCommunity(CheckPointSourceObject):
    community_type: str | None = None
    participating_gateways: list[CheckPointObjectReference | str] | None = None
    center: list[CheckPointObjectReference | str] | None = None
    satellites: list[CheckPointObjectReference | str] | None = None
    encryption_method: str | None = None
    ike_properties: dict | None = None
    ipsec_properties: dict | None = None
    vpn_domain: CheckPointObjectReference | str | None = None
    psk_configured: bool | None = None


class CPVPNDomain(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] | None = None


__all__ = ["CPVPNCommunity", "CPVPNDomain"]
