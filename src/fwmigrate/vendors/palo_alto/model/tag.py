from __future__ import annotations

from .common import PANNamedSourceModel


class PANTag(PANNamedSourceModel):
    color: str | None = None
    comments: str | None = None
