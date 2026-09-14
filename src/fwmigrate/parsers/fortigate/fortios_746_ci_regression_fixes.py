"""Compatibility fixes for FortiOS 7.4.6 address IR regressions."""

from __future__ import annotations

from typing import Any, List

from pydantic import Field, field_validator


def install_fortios_746_ci_regression_fixes(
    transformer_module: Any,
    coverage_module: Any,
) -> None:
    """Keep audited 7.4.6 address semantics compatible with existing IR logic."""

    # address6-template is typed source inventory, not portable canonical address
    # intent. Keep its coverage classification aligned with the extraction model.
    coverage_module.TYPED_EXTRACT_ONLY_SECTIONS.add("firewall address6-template")

    active_ir_address = transformer_module.IRAddress
    if active_ir_address.__name__ != "IRAddress746Compat":
        class IRAddress746Compat(active_ir_address):
            source_fsso_group: List[str] = Field(default_factory=list)

            @field_validator("source_fsso_group", mode="before")
            @classmethod
            def _normalize_source_fsso_group(cls, value: Any) -> Any:
                return [] if value is None else value

        transformer_module.IRAddress = IRAddress746Compat

    transformer_cls = transformer_module.FGToIRTransformer
    current_transform = transformer_cls._transform_addresses
    if not getattr(current_transform, "_fortios_746_empty_fsso_fixed", False):
        def _transform_addresses(self: Any) -> None:
            # PR #77 changed fsso-group from an optional scalar to a list. An empty
            # list means the setting is absent; older review logic uses None for
            # that state. Normalize only the absent case before that logic runs.
            for address in self.fg.addresses:
                if getattr(address, "fsso_group", None) == []:
                    address.fsso_group = None
            current_transform(self)

        _transform_addresses._fortios_746_empty_fsso_fixed = True
        transformer_cls._transform_addresses = _transform_addresses
