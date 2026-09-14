"""Compatibility fixes for FortiOS 7.4.6 address IR regressions."""

from __future__ import annotations

from typing import Any, List

from pydantic import Field, field_validator


def install_fortios_746_ci_regression_fixes(transformer_module: Any) -> None:
    """Keep the multi-value FSSO field compatible with legacy None inputs."""

    active_ir_address = transformer_module.IRAddress
    if active_ir_address.__name__ == "IRAddress746Compat":
        return

    class IRAddress746Compat(active_ir_address):
        source_fsso_group: List[str] = Field(default_factory=list)

        @field_validator("source_fsso_group", mode="before")
        @classmethod
        def _normalize_source_fsso_group(cls, value: Any) -> Any:
            return [] if value is None else value

    transformer_module.IRAddress = IRAddress746Compat
