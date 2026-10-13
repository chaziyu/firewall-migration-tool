from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GaiaCommandNode:
    operation: str
    arguments: tuple[str, ...]
    line_number: int


@dataclass(frozen=True)
class GaiaUnknownCommandNode:
    operation: str
    arguments: tuple[str, ...]
    line_number: int
    reason: str = "unsupported"


@dataclass(frozen=True)
class GaiaCommentNode:
    value: str
    line_number: int


@dataclass
class GaiaConfigTree:
    commands: list[GaiaCommandNode] = field(default_factory=list)
    comments: list[GaiaCommentNode] = field(default_factory=list)
    unknown_commands: list[GaiaUnknownCommandNode] = field(default_factory=list)
