from typing import Any

from pydantic import BaseModel, Field


class FGSessionHelper(BaseModel):
    id: int | None = None
    name: str | None = None
    port: int | None = None
    protocol: int | None = None
    vdom: str = "root"
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
