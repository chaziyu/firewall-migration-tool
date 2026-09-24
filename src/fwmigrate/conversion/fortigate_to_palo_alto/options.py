"""Explicit target mappings for FortiGate to Palo Alto planning."""

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True, slots=True)
class VDOMMapping:
    vsys: str | None = None
    virtual_router: str | None = None


@dataclass(frozen=True, slots=True)
class InterfaceMapping:
    target_interface: str | None = None
    target_zone: str | None = None


@dataclass(frozen=True, slots=True)
class PANMigrationOptions:
    """Mappings required to make source-to-target ownership explicit."""

    vdoms: Mapping[str, VDOMMapping | Mapping[str, str | None]] = field(default_factory=dict)
    interfaces: Mapping[str, Mapping[str, InterfaceMapping | Mapping[str, str | None]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "vdoms", self._coerce(self.vdoms, VDOMMapping))
        object.__setattr__(self, "interfaces", {
            vdom: self._coerce(mappings, InterfaceMapping)
            for vdom, mappings in (self.interfaces or {}).items()
        })

    @staticmethod
    def _coerce(values, value_type):
        if not values:
            return {}
        return {
            name: value if isinstance(value, value_type) else value_type(**value)
            for name, value in values.items()
        }
