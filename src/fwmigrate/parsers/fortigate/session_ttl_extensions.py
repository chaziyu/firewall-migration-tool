"""FortiOS session-timeout source models and section metadata."""

from __future__ import annotations

from typing import Any, List, Literal, Optional, Union

from pydantic import Field, SerializeAsAny, model_validator

from fwmigrate.parsers.fortigate import model as model_module
from fwmigrate.parsers.fortigate.model import _preserve_malformed_int_fields


SYSTEM_GLOBAL_SESSION_TIMER_FIELDS = {
    "tcp_halfclose_timer",
    "tcp_halfopen_timer",
    "tcp_rst_timer",
    "tcp_timewait_timer",
    "udp_idle_timer",
}

SESSION_TTL_OVERRIDE_INT_FIELDS = {
    "protocol",
    "start_port",
    "end_port",
}


_BaseFGSystemGlobal = model_module.FGSystemGlobal
_BaseFGService = model_module.FGService
_BaseFGConfig = model_module.FGConfig


class FGSystemGlobalSessionTimers(_BaseFGSystemGlobal):
    """Typed FortiOS global session timers without target-side interpretation."""

    tcp_halfclose_timer: Optional[int] = None
    tcp_halfopen_timer: Optional[int] = None
    tcp_rst_timer: Optional[int] = None
    tcp_timewait_timer: Optional[int] = None
    udp_idle_timer: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_session_timer_fields(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            SYSTEM_GLOBAL_SESSION_TIMER_FIELDS,
        )


class FGServiceSessionTimers(_BaseFGService):
    """FortiOS custom-service timeout settings kept separate per service."""

    session_ttl: Optional[Union[int, Literal["never"]]] = None
    tcp_halfclose_timer: Optional[int] = None
    tcp_halfopen_timer: Optional[int] = None
    tcp_rst_timer: Optional[int] = None
    tcp_timewait_timer: Optional[int] = None
    udp_idle_timer: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_session_timer_fields(cls, value: Any) -> Any:
        normalized = _preserve_malformed_int_fields(
            value,
            SYSTEM_GLOBAL_SESSION_TIMER_FIELDS,
        )
        if not isinstance(normalized, dict):
            return normalized

        raw_session_ttl = normalized.get("session_ttl")
        if raw_session_ttl is None:
            return normalized

        if isinstance(raw_session_ttl, str) and raw_session_ttl.lower() == "never":
            normalized = dict(normalized)
            normalized["session_ttl"] = "never"
            extra_settings = dict(normalized.get("extra_settings") or {})
            extra_settings.pop("unparsed_session_ttl", None)
            normalized["extra_settings"] = extra_settings
            return normalized

        return _preserve_malformed_int_fields(normalized, {"session_ttl"})


class FGConfigSessionTimers(_BaseFGConfig):
    """Compatibility root model retaining the typed timeout subclasses."""

    system_global: Optional[SerializeAsAny[FGSystemGlobalSessionTimers]] = None
    services: List[SerializeAsAny[FGServiceSessionTimers]] = Field(default_factory=list)
