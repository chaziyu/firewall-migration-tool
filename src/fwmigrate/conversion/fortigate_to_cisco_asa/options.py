"""Explicit source scope and ASA placement choices."""

from dataclasses import dataclass, field
import re


@dataclass(frozen=True, slots=True)
class ASATargetInterface:
    interface: str
    nameif: str
    security_level: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:/-]{0,63}", self.interface):
            raise ValueError("ASA interface must be an explicit interface identifier")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,47}", self.nameif):
            raise ValueError("ASA nameif must contain 1 to 48 safe characters")
        if type(self.security_level) is not int or not 0 <= self.security_level <= 100:
            raise ValueError("ASA security level must be an integer from 0 through 100")


@dataclass(frozen=True, slots=True)
class ASAMigrationOptions:
    source_vdom: str | None = None
    target_context: str | None = None
    target_version: str | None = None
    target_mode: str | None = None
    interfaces: dict[str, dict[str, ASATargetInterface | dict]] = field(default_factory=dict)
    source_timezone: str | None = None
    target_timezone: str | None = None
    nat_evidence: dict[str, dict[str, bool]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        parsed = {}
        for vdom, mappings in self.interfaces.items():
            if not isinstance(vdom, str) or not isinstance(mappings, dict):
                raise ValueError("ASA interface mappings must be grouped by FortiGate VDOM")
            parsed[vdom] = {
                name: value if isinstance(value, ASATargetInterface) else ASATargetInterface(**value)
                for name, value in mappings.items()
            }
        object.__setattr__(self, "interfaces", parsed)
        if not isinstance(self.nat_evidence, dict):
            raise ValueError("ASA NAT evidence must be an object")
        for key, evidence in self.nat_evidence.items():
            if not isinstance(key, str) or not isinstance(evidence, dict) or any(type(value) is not bool for value in evidence.values()):
                raise ValueError("ASA NAT evidence must contain explicit boolean decisions")

    def to_dict(self) -> dict:
        return {
            "source_vdom": self.source_vdom,
            "target_context": self.target_context,
            "target_version": self.target_version,
            "target_mode": self.target_mode,
            "interfaces": {
                vdom: {name: {"interface": row.interface, "nameif": row.nameif,
                              "security_level": row.security_level}
                       for name, row in mappings.items()}
                for vdom, mappings in self.interfaces.items()
            },
            "source_timezone": self.source_timezone,
            "target_timezone": self.target_timezone,
            "nat_evidence": self.nat_evidence,
        }
