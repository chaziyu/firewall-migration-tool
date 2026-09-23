from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPThreatProfile(CheckPointSourceObject):
    settings: dict | None = None


class CPThreatLayer(CheckPointSourceObject):
    profiles: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPThreatSection(CheckPointSourceObject):
    section_path: list[str] = Field(default_factory=list)


class CPThreatPreventionRule(CheckPointSourceObject):
    section_path: list[str] = Field(default_factory=list)
    rule_number: int | None = Field(default=None, alias="rule-number")
    enabled: bool | None = None
    profile: str | None = None
    source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    install_on: list[CheckPointObjectReference | str] = Field(default_factory=list, alias="install-on")


class CPThreatRule(CPThreatPreventionRule):
    pass


class CPThreatRuleException(CPThreatPreventionRule):
    exception: str | None = None


class CPHTTPSInspectionRule(CheckPointSourceObject):
    section_path: list[str] = Field(default_factory=list)
    rule_number: int | None = Field(default=None, alias="rule-number")
    enabled: bool | None = None
    profile: str | None = None
    source: list[CheckPointObjectReference | str] = Field(default_factory=list)
    destination: list[CheckPointObjectReference | str] = Field(default_factory=list)
    install_on: list[CheckPointObjectReference | str] = Field(default_factory=list, alias="install-on")


__all__ = [
    "CPHTTPSInspectionRule", "CPThreatLayer", "CPThreatPreventionRule", "CPThreatProfile",
    "CPThreatRule", "CPThreatRuleException", "CPThreatSection",
]
