"""Explicit source ownership and target placement for Juniper SRX."""

from dataclasses import asdict, dataclass, field
import re


@dataclass(frozen=True, slots=True)
class SRXInterfaceMapping:
    target_interface: str
    unit: int = 0
    tag: int | None = None

    def __post_init__(self):
        if not isinstance(self.target_interface, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9/:-]{0,62}", self.target_interface):
            raise ValueError("Target interface must be a Junos physical interface name")
        if type(self.unit) is not int or not 0 <= self.unit <= 16385:
            raise ValueError("Target logical unit must be between 0 and 16385")
        if self.tag is not None and (type(self.tag) is not int or not 1 <= self.tag <= 4094):
            raise ValueError("VLAN tag must be between 1 and 4094")


@dataclass(frozen=True, slots=True)
class SRXMigrationOptions:
    source_scope: str | None = None
    target_context: str = "root"
    target_version: str = "25.2R1"
    target_mode: str = "standalone"
    interfaces: dict[str, SRXInterfaceMapping | dict] = field(default_factory=dict)
    zones: dict[str, str] = field(default_factory=dict)
    interface_zones: dict[str, str] = field(default_factory=dict)
    routing_table: str = "inet.0"
    vlan_interfaces_available: bool = False

    def __post_init__(self):
        if self.source_scope is not None and (not isinstance(self.source_scope, str) or not self.source_scope.strip()):
            raise ValueError("source_scope must be a nonempty source identity")
        for field_name in ("target_context", "target_version", "routing_table"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
                raise ValueError(f"{field_name} must be explicit text")
        if self.target_mode != "standalone" or self.target_version != "25.2R1":
            raise ValueError("Initial PAN-OS to SRX support is standalone Junos 25.2R1")
        if type(self.vlan_interfaces_available) is not bool:
            raise ValueError("vlan_interfaces_available must be a boolean")
        parsed = {key: value if isinstance(value, SRXInterfaceMapping) else SRXInterfaceMapping(**value)
                  for key, value in self.interfaces.items()}
        for mapping in (*self.zones.items(), *self.interface_zones.items()):
            key, value = mapping
            if not isinstance(key, str) or not key or not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", value):
                raise ValueError("Zone mappings require source names and valid Junos zone names")
        object.__setattr__(self, "interfaces", parsed)
        object.__setattr__(self, "zones", dict(self.zones))
        object.__setattr__(self, "interface_zones", dict(self.interface_zones))

    def to_dict(self):
        return asdict(self)
