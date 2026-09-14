# Canonical IR provenance domain models

from typing import List
from pydantic import BaseModel, Field


class IRSourceConfigCommand(BaseModel):
    """Sanitized source configuration command."""

    operation: str
    key: str
    values: List[str] = Field(
        default_factory=list
    )
class IRSourceConfigNode(BaseModel):
    node_type: str
    name: str

    commands: List[
        IRSourceConfigCommand
    ] = Field(default_factory=list)

    children: List[
        "IRSourceConfigNode"
    ] = Field(default_factory=list)


__all__ = [
    "IRSourceConfigCommand",
    "IRSourceConfigNode",
]
