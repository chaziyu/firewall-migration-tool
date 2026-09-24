from __future__ import annotations
from typing import List
from pydantic import Field
from .base import CiscoSourceRecord


class CiscoTrafficZone(CiscoSourceRecord):
    members: List[str] = Field(default_factory=list)
