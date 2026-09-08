"""FortiOS 7.4.6 session-timeout parser extensions.

Keep the distinct FortiOS timeout scopes separate:
- ``system session-ttl`` default and per-port/protocol overrides;
- ``system global`` TCP/UDP timers;
- ``firewall service custom`` service-specific session timers.

The extension follows the parser's zero-silent-loss convention: malformed
numeric values are not repaired or defaulted. They remain sanitized under an
``unparsed_*`` key in ``extra_settings`` while the typed field is left unset.
"""

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
    """Root model specialization that serializes extended nested model fields."""

    system_global: Optional[SerializeAsAny[FGSystemGlobalSessionTimers]] = None
    services: List[SerializeAsAny[FGServiceSessionTimers]] = Field(default_factory=list)


def install_session_ttl_extensions(parser_module) -> None:
    """Install Phase 1 session-timeout coverage on the FortiGate parser."""

    parser_cls = parser_module.FortiGateParser

    model_module.FGSystemGlobal = FGSystemGlobalSessionTimers
    model_module.FGService = FGServiceSessionTimers
    model_module.FGConfig = FGConfigSessionTimers
    parser_module.FGSystemGlobal = FGSystemGlobalSessionTimers
    parser_module.FGService = FGServiceSessionTimers
    parser_module.FGConfig = FGConfigSessionTimers

    if not getattr(parser_cls.build_model, "_session_ttl_phase1_wrapped", False):
        original_build_model = parser_cls.build_model

        def build_model(self, section_path, attributes):
            raw_service_session_ttl = None
            if section_path == "firewall service custom":
                raw_service_session_ttl = attributes.get("session_ttl")
                for field in SYSTEM_GLOBAL_SESSION_TIMER_FIELDS:
                    self._normalize_optional_int(attributes, field)

                if raw_service_session_ttl is not None:
                    if (
                        isinstance(raw_service_session_ttl, str)
                        and raw_service_session_ttl.lower() == "never"
                    ):
                        attributes["session_ttl"] = "never"
                        extra_settings = attributes.get("extra_settings")
                        if isinstance(extra_settings, dict):
                            extra_settings.pop("unparsed_session_ttl", None)
                    else:
                        self._normalize_optional_int(attributes, "session_ttl")

            elif section_path == "system session-ttl port":
                for field in SESSION_TTL_OVERRIDE_INT_FIELDS:
                    self._normalize_optional_int(attributes, field)

                timeout = attributes.get("timeout")
                if timeout is not None and not (
                    isinstance(timeout, str) and timeout.lower() == "never"
                ):
                    self._normalize_optional_int(attributes, "timeout")

            result = original_build_model(self, section_path, attributes)

            if (
                section_path == "firewall service custom"
                and raw_service_session_ttl is not None
                and self.config.services
            ):
                service = self.config.services[-1]
                if service.session_ttl is not None:
                    service.extra_settings["session_ttl"] = str(service.session_ttl)

            return result

        build_model._session_ttl_phase1_wrapped = True
        parser_cls.build_model = build_model

    if not getattr(parser_cls.apply_global_set, "_session_ttl_phase1_wrapped", False):
        original_apply_global_set = parser_cls.apply_global_set

        def apply_global_set(self, section_path, key, values):
            clean_key = key.replace("-", "_")

            if section_path == "system global" and clean_key in SYSTEM_GLOBAL_SESSION_TIMER_FIELDS:
                if not self.config.system_global:
                    self.config.system_global = FGSystemGlobalSessionTimers(hostname=None)

                self.config.system_global.extra_settings.pop(
                    f"unparsed_{clean_key}", None
                )
                self.config.system_global.extra_settings.pop(clean_key, None)

                raw_value = values[0] if len(values) == 1 else " ".join(values)
                candidate = {clean_key: raw_value}
                self._normalize_optional_int(candidate, clean_key)
                if clean_key in candidate:
                    setattr(self.config.system_global, clean_key, candidate[clean_key])
                else:
                    setattr(self.config.system_global, clean_key, None)
                    unparsed_key = f"unparsed_{clean_key}"
                    if unparsed_key in candidate:
                        self.config.system_global.extra_settings.update(
                            parser_module.sanitize_source_attributes(
                                {unparsed_key: candidate[unparsed_key]}
                            )
                        )
                return

            if section_path == "system session-ttl" and clean_key == "default":
                if not self.config.session_ttl_settings:
                    self.config.session_ttl_settings = parser_module.FGSessionTTLSettings()

                settings = self.config.session_ttl_settings
                settings.extra_settings.pop("unparsed_default", None)
                settings.extra_settings.pop("default", None)

                if values and values[0].lower() == "never":
                    settings.default_timeout = None
                    settings.default_never = True
                    return

                raw_value = values[0] if len(values) == 1 else " ".join(values)
                candidate = {"default_timeout": raw_value}
                self._normalize_optional_int(candidate, "default_timeout")
                if "default_timeout" in candidate:
                    settings.default_timeout = candidate["default_timeout"]
                    settings.default_never = False
                else:
                    settings.default_timeout = None
                    settings.default_never = False
                    if "unparsed_default_timeout" in candidate:
                        settings.extra_settings.update(
                            parser_module.sanitize_source_attributes(
                                {"unparsed_default": candidate["unparsed_default_timeout"]}
                            )
                        )
                return

            return original_apply_global_set(self, section_path, key, values)

        apply_global_set._session_ttl_phase1_wrapped = True
        parser_cls.apply_global_set = apply_global_set

    if not getattr(parser_cls.apply_global_unset, "_session_ttl_phase1_wrapped", False):
        original_apply_global_unset = parser_cls.apply_global_unset

        def apply_global_unset(self, section_path, key):
            clean_key = key.replace("-", "_")

            if section_path == "system global" and clean_key in SYSTEM_GLOBAL_SESSION_TIMER_FIELDS:
                if self.config.system_global:
                    setattr(self.config.system_global, clean_key, None)
                    self.config.system_global.extra_settings.pop(clean_key, None)
                    self.config.system_global.extra_settings.pop(
                        f"unparsed_{clean_key}", None
                    )
                return

            if section_path == "system session-ttl" and clean_key == "default":
                if self.config.session_ttl_settings:
                    self.config.session_ttl_settings.default_timeout = None
                    self.config.session_ttl_settings.default_never = False
                    self.config.session_ttl_settings.extra_settings.pop(
                        "unparsed_default", None
                    )
                    self.config.session_ttl_settings.extra_settings.pop(
                        "default", None
                    )
                return

            return original_apply_global_unset(self, section_path, key)

        apply_global_unset._session_ttl_phase1_wrapped = True
        parser_cls.apply_global_unset = apply_global_unset


def install_final_session_ttl_serialization(parser_module) -> None:
    """Compose Phase 1 serialization with the final active FortiGate root model.

    Later parser phases replace ``parser_module.FGConfig`` with stricter
    supersets. A parser instance can therefore be created with a root model
    whose serializer predates Phase 1 even though its nested objects carry the
    new timer attributes. Finalize the parsed result into a subclass of the
    final active root model and keep nested Pydantic objects verbatim so their
    runtime serializers retain all typed fields.
    """

    parser_cls = parser_module.FortiGateParser
    active_root = parser_module.FGConfig

    class FGConfigSessionTTLFinal(active_root):
        system_global: Optional[Any] = None
        services: List[Any] = Field(default_factory=list)
        system_fsso_polling: Optional[Any] = None

    parser_module.FGConfig = FGConfigSessionTTLFinal
    model_module.FGConfig = FGConfigSessionTTLFinal

    if getattr(parser_cls.parse, "_session_ttl_finalized", False):
        return

    original_parse = parser_cls.parse

    def parse(self):
        parsed = original_parse(self)
        if isinstance(parsed, FGConfigSessionTTLFinal):
            return parsed

        values = {
            field_name: getattr(parsed, field_name)
            for field_name in FGConfigSessionTTLFinal.model_fields
            if hasattr(parsed, field_name)
        }
        return FGConfigSessionTTLFinal.model_construct(**values)

    parse._session_ttl_finalized = True
    parser_cls.parse = parse
