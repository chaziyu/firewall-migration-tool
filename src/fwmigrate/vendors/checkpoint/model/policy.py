from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPPolicyPackage(CheckPointSourceObject):
    access_layers: list[CheckPointObjectReference | str] | None = None


class CPAccessLayer(CheckPointSourceObject):
    pass


class CPAccessSection(CheckPointSourceObject):
    pass


class _CPOrderedPolicyRule(CheckPointSourceObject):
    rule_number: int | None = Field(default=None, alias="rule-number")
    enabled: bool | None = None


class CPAccessRule(_CPOrderedPolicyRule):
    source: list[CheckPointObjectReference | str] | None = None
    destination: list[CheckPointObjectReference | str] | None = None
    service: list[CheckPointObjectReference | str] | None = None
    services_and_applications: list[CheckPointObjectReference | str] | None = Field(default=None, alias="services-and-applications")
    vpn: list[CheckPointObjectReference | str] | None = None
    content: list[CheckPointObjectReference | str] | None = None
    source_negate: bool | None = Field(default=None, alias="source-negate")
    destination_negate: bool | None = Field(default=None, alias="destination-negate")
    install_on: list[CheckPointObjectReference | str] | None = Field(default=None, alias="install-on")
    time: list[CheckPointObjectReference | str] | None = None
    action: CheckPointObjectReference | str | None = None
    track: CheckPointObjectReference | str | None = None
    inline_layer: CheckPointObjectReference | str | None = Field(default=None, alias="inline-layer")


class CPNATSection(CheckPointSourceObject):
    pass


class CPManualNATRule(_CPOrderedPolicyRule):
    original_source: list[CheckPointObjectReference | str] | None = None
    original_destination: list[CheckPointObjectReference | str] | None = None
    original_service: list[CheckPointObjectReference | str] | None = None
    translated_source: list[CheckPointObjectReference | str] | None = None
    translated_destination: list[CheckPointObjectReference | str] | None = None
    translated_service: list[CheckPointObjectReference | str] | None = None
    install_on: list[CheckPointObjectReference | str] | None = Field(default=None, alias="install-on")


class CPAutoNATRule(_CPOrderedPolicyRule):
    """Compatibility model for returned generated Automatic NAT evidence.

    Live/source extraction does not place this type in CheckPointConfig.
    """

    original_source: list[CheckPointObjectReference | str] | None = None
    original_destination: list[CheckPointObjectReference | str] | None = None
    original_service: list[CheckPointObjectReference | str] | None = None
    translated_source: list[CheckPointObjectReference | str] | None = None
    translated_destination: list[CheckPointObjectReference | str] | None = None
    translated_service: list[CheckPointObjectReference | str] | None = None
    automatic: bool | None = None


class CPNATRule(CPManualNATRule):
    method: str | None = None
    translation_metadata: dict | None = None


__all__ = [
    "CPAccessLayer", "CPAccessRule", "CPAutoNATRule", "CPManualNATRule", "CPNATRule",
    "CPNATSection", "CPPolicyPackage", "CPAccessSection",
]
