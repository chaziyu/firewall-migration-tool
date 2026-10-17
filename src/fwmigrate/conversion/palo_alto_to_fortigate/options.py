"""Explicit engineer proposals for one selected PAN-OS VSYS."""
from dataclasses import asdict, dataclass, field
import re


def safe_text(value, *, limit=255, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value.strip()) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Expected a nonempty value without control characters")
    return value


@dataclass(frozen=True, slots=True)
class FGMigrationOptions:
    source_scope: str = ""
    vdom: str = ""
    interfaces: dict = field(default_factory=dict)
    zones: dict = field(default_factory=dict)
    routers: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)
    timezone: str = ""
    policy_settings: dict = field(default_factory=dict)

    def __post_init__(self):
        for name in ("source_scope", "vdom", "timezone"):
            value = getattr(self, name)
            if value:
                safe_text(value)
            elif not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
        if self.vdom and not re.fullmatch(r"[A-Za-z0-9_.-]{1,31}", self.vdom):
            raise ValueError("Invalid target VDOM name")
        for name in ("interfaces", "zones", "routers", "profile", "policy_settings"):
            value = getattr(self, name)
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be an object")
            object.__setattr__(self, name, dict(value))
        for key, values in self.policy_settings.items():
            safe_text(key, limit=2048)
            if not isinstance(values, dict) or set(values) - {"schedule", "disabled", "log_start", "log_end", "negate_source", "negate_destination", "rule_type", "source_user", "category"}:
                raise ValueError("Invalid per-policy target choices")
            for value in values.values():
                safe_text(value)
        for name in ("interfaces", "zones"):
            for key, value in getattr(self, name).items():
                safe_text(key)
                limit = 15 if name == "interfaces" else 35
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1," + str(limit) + "}", safe_text(value)):
                    raise ValueError(f"Invalid target {name} name")
                if value.casefold() in {"any", "all"}:
                    raise ValueError("Reserved wildcard names cannot be used for target placement")
        if set(self.interfaces.values()) & set(self.zones.values()):
            raise ValueError("Target zones and interfaces must have distinct names")
        for key, value in self.routers.items():
            safe_text(key)
            if type(value) is not int or not 0 <= value <= 251:
                raise ValueError("Target VRF must be an integer from 0 to 251")
        allowed = {"fortios_version", "operating_mode", "ngfw_mode", "nat_mode", "vdom_mode", "ports", "pool_return_routing", "traffic_baseline", "vip_arp_reply"}
        if set(self.profile) - allowed:
            raise ValueError("Unknown FortiGate target profile setting")
        for key, value in self.profile.items():
            if key == "ports":
                if not isinstance(value, list) or any(not isinstance(port, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", port) for port in value):
                    raise ValueError("Target ports must be explicit interface names")
            else:
                safe_text(value)

    def to_dict(self):
        return asdict(self)
