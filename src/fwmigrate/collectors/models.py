from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class ConnectionResult(BaseModel):
    success: bool
    vendor: str
    hostname: Optional[str] = None
    software_version: Optional[str] = None
    message: str = ""
    warnings: List[str] = Field(default_factory=list)


class SourceSnapshot(BaseModel):
    vendor: str
    hostname: Optional[str] = None
    software_version: Optional[str] = None
    raw_config: str
    collection_method: str
    commands_executed: List[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    complete: bool = False
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    sha256: str = ""

    def model_post_init(self, __context) -> None:
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.raw_config.encode("utf-8")).hexdigest()
