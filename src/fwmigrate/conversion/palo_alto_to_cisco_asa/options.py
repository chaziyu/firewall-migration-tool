"""Explicit ASA 9.20 routed single-context design decisions."""

from dataclasses import asdict, dataclass, field
import re


@dataclass(frozen=True, slots=True)
class ASAInterfaceMapping:
    target_interface: str
    nameif: str
    security_level: int

    def __post_init__(self):
        if not isinstance(self.target_interface, str) or not re.fullmatch(r"(?:GigabitEthernet|TenGigabitEthernet|Ethernet)[0-9]+(?:/[0-9]+){1,2}", self.target_interface):
            raise ValueError("Choose an explicit supported ASA physical Ethernet port")
        if not isinstance(self.nameif, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,47}", self.nameif):
            raise ValueError("Choose a valid explicit ASA nameif")
        if type(self.security_level) is not int or not 0 <= self.security_level <= 100:
            raise ValueError("security_level must be an integer from 0 to 100")


@dataclass(frozen=True, slots=True)
class ASAMigrationOptions:
    source_scope: str | None = None
    target_context: str = "single"
    target_version: str = "9.20"
    target_mode: str = "routed"
    interfaces: dict[str, ASAInterfaceMapping | dict] = field(default_factory=dict)
    new_target_confirmed: bool = False
    routing_complete: bool = False
    permit_inter_interface: bool = False
    permit_intra_interface: bool = False
    ace_limit: int = 256

    def __post_init__(self):
        if self.source_scope is not None and (not isinstance(self.source_scope, str) or not self.source_scope.strip()):
            raise ValueError("source_scope must be a native PAN-OS scope identity")
        if (self.target_context, self.target_version, self.target_mode) != ("single", "9.20", "routed"):
            raise ValueError("Initial support requires ASA 9.20 routed single context")
        for name in ("new_target_confirmed", "routing_complete", "permit_inter_interface", "permit_intra_interface"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} requires an explicit boolean")
        if type(self.ace_limit) is not int or not 1 <= self.ace_limit <= 1024:
            raise ValueError("ace_limit must be between 1 and 1024")
        if not isinstance(self.interfaces, dict) or any(not isinstance(key, str) or not key for key in self.interfaces):
            raise ValueError("interfaces must be keyed by source interface name")
        parsed = {key: value if isinstance(value, ASAInterfaceMapping) else ASAInterfaceMapping(**value)
                  for key, value in self.interfaces.items()}
        for attribute in ("target_interface", "nameif"):
            values = [getattr(row, attribute).casefold() for row in parsed.values()]
            if len(values) != len(set(values)):
                raise ValueError("Target interfaces and nameifs must be unique")
        object.__setattr__(self, "interfaces", parsed)

    def to_dict(self):
        return asdict(self)
