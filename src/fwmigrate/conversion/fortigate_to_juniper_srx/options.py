"""Explicit source-scope and target-placement choices for Juniper SRX."""

from dataclasses import dataclass, field
import re


@dataclass(frozen=True, slots=True)
class SRXInterfaceMapping:
    target_interface: str
    unit: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9/:-]*", self.target_interface):
            raise ValueError("Target physical interface must be a Junos interface name")
        if type(self.unit) is not int or not 0 <= self.unit <= 16385:
            raise ValueError("Target logical unit must be an integer from 0 through 16385")


@dataclass(frozen=True, slots=True)
class SRXMigrationOptions:
    source_vdom: str | None = None
    target_context: str | None = None
    target_version: str | None = None
    target_mode: str | None = None
    routing_table: str | None = None
    interfaces: dict[str, dict[str, SRXInterfaceMapping | dict]] = field(default_factory=dict)
    zones: dict[str, dict[str, str]] = field(default_factory=dict)
    timezone: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "interfaces", {
            vdom: {
                name: value if isinstance(value, SRXInterfaceMapping) else SRXInterfaceMapping(**value)
                for name, value in mappings.items()
            }
            for vdom, mappings in self.interfaces.items()
        })

