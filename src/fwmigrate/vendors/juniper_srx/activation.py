"""Derived Junos activate/deactivate hierarchy state."""

from __future__ import annotations

from collections.abc import Sequence

from fwmigrate.extraction.models import ExtractionStatus
from .tokenizer import JunosCommand, JunosOperation


class JunosActivationState:
    """Track explicit activate/deactivate directives for effective-state derivation."""

    def __init__(self) -> None:
        self.inactive_paths: list[list[str]] = []

    def apply(self, commands: Sequence[JunosCommand]) -> None:
        for cmd in commands:
            if cmd.operation == JunosOperation.DEACTIVATE:
                if len(cmd.tokens) > 1:
                    path = [token.lower() for token in cmd.tokens[1:]]
                    if path not in self.inactive_paths:
                        self.inactive_paths.append(path)
                cmd.consumed = True
                cmd.extraction_status = ExtractionStatus.EXTRACTED
            elif cmd.operation == JunosOperation.ACTIVATE:
                if len(cmd.tokens) > 1:
                    path = [token.lower() for token in cmd.tokens[1:]]
                    self.inactive_paths = [
                        candidate for candidate in self.inactive_paths
                        if candidate[:len(path)] != path
                    ]
                cmd.consumed = True
                cmd.extraction_status = ExtractionStatus.EXTRACTED

    def is_inactive(self, path: Sequence[str]) -> bool:
        normalized = [token.lower() for token in path]
        return any(
            len(normalized) >= len(parent) and normalized[:len(parent)] == parent
            for parent in self.inactive_paths
        )

    def is_exactly_inactive(self, path: Sequence[str]) -> bool:
        return [token.lower() for token in path] in self.inactive_paths
