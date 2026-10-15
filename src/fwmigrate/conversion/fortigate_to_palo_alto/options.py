"""Explicit target mappings for FortiGate to Palo Alto planning."""

from dataclasses import dataclass, field
from typing import Mapping
import re
from .target.profile import parse_conversion_settings


@dataclass(frozen=True, slots=True)
class VDOMMapping:
    vsys: str | None = None
    virtual_router: str | None = None


@dataclass(frozen=True, slots=True)
class InterfaceMapping:
    target_interface: str | None = None
    target_zone: str | None = None


@dataclass(frozen=True, slots=True)
class ZoneMapping:
    target_zone: str | None = None


@dataclass(frozen=True, slots=True)
class PANMigrationOptions:
    """Mappings required to make source-to-target ownership explicit."""

    vdoms: Mapping[str, VDOMMapping | Mapping[str, str | None]] = field(default_factory=dict)
    interfaces: Mapping[str, Mapping[str, InterfaceMapping | Mapping[str, str | None]]] = field(default_factory=dict)
    zones: Mapping[str, Mapping[str, ZoneMapping | Mapping[str, str | None]]] | None = None
    service_names: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    conversion_settings: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'conversion_settings', parse_conversion_settings(self.conversion_settings))
        if not isinstance(self.service_names, Mapping) or any(
            not isinstance(vdom, str) or not vdom or not isinstance(names, Mapping)
            or any(not isinstance(name, str) or not name or not isinstance(value, str)
                   or not re.fullmatch(r"[A-Za-z0-9_. -]{1,63}", value) or not value.strip()
                   or value in {"any", "application-default", "service-http", "service-https"}
                   for name, value in names.items())
            for vdom, names in self.service_names.items()
        ):
            raise ValueError("service_names must contain scoped source names and valid target service names")
        object.__setattr__(self, "service_names", {vdom: dict(names) for vdom, names in self.service_names.items()})
        object.__setattr__(self, "vdoms", self._coerce(self.vdoms, VDOMMapping))
        object.__setattr__(self, "interfaces", {
            vdom: self._coerce(mappings, InterfaceMapping)
            for vdom, mappings in (self.interfaces or {}).items()
        })
        if self.zones is not None:
            object.__setattr__(self, "zones", {
                vdom: self._coerce(mappings, ZoneMapping)
                for vdom, mappings in self.zones.items()
            })

    @staticmethod
    def _coerce(values, value_type):
        if not values:
            return {}
        return {
            name: value if isinstance(value, value_type) else value_type(**value)
            for name, value in values.items()
        }
