from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPPolicyPackage(CheckPointSourceObject):
    access_layers: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPAccessLayer(CheckPointSourceObject):
    pass


class CPAccessSection(CheckPointSourceObject):
    section_path: list[str] = Field(default_factory=list)


class CPAccessRule(CheckPointSourceObject):
    rule_number: int | None = Field(default=None, alias="rule-number")
    enabled: bool | None = None
    section_path: list[str] = Field(default_factory=list)
    source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    service: list[CheckPointObjectReference | str] = Field(default_factory=list)
    services_and_applications: list[CheckPointObjectReference | str] = Field(default_factory=list, alias="services-and-applications")
    vpn: list[CheckPointObjectReference | str] = Field(default_factory=list)
    content: list[CheckPointObjectReference | str] = Field(default_factory=list)
    source_negate: bool | None = Field(default=None, alias="source-negate")
    destination_negate: bool | None = Field(default=None, alias="destination-negate")
    install_on: list[CheckPointObjectReference | str] = Field(default_factory=list, alias="install-on")
    time: list[CheckPointObjectReference | str] = Field(default_factory=list)
    action: CheckPointObjectReference | str | None = None
    track: CheckPointObjectReference | str | None = None
    inline_layer: CheckPointObjectReference | str | None = Field(default=None, alias="inline-layer")


class CPNATSection(CheckPointSourceObject):
    section_path: list[str] = Field(default_factory=list)


class CPManualNATRule(CPAccessRule):
    original_source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    original_destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    original_service: list[CheckPointObjectReference | str] = Field(default_factory=list)
    translated_source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    translated_destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    translated_service: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPAutoNATRule(CheckPointSourceObject):
    original_source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    original_destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    original_service: list[CheckPointObjectReference | str] = Field(default_factory=list)
    translated_source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    translated_destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    translated_service: list[CheckPointObjectReference | str] = Field(default_factory=list)
    automatic: bool | None = None


class CPNATRule(CPManualNATRule):
    method: str | None = None
    translation_metadata: dict | None = None


__all__ = [
    "CPAccessLayer", "CPAccessRule", "CPAutoNATRule", "CPManualNATRule", "CPNATRule",
    "CPNATSection", "CPPolicyPackage", "CPAccessSection",
]
