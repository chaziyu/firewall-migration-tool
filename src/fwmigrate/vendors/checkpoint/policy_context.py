"""Structural policy context derived from native Check Point rulebase nesting."""

from __future__ import annotations

from dataclasses import dataclass

from .model.common import CheckPointSourceObject


@dataclass(frozen=True, slots=True)
class CPPolicyContextRecord:
    """Read-only structural provenance kept outside VendorConfig."""

    source: CheckPointSourceObject
    section_path: tuple[str, ...] = ()


__all__ = ["CPPolicyContextRecord"]
