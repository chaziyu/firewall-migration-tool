"""Outward compatibility facade for Check Point configuration parser."""

from __future__ import annotations

from typing import Dict, Optional
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


class CheckPointParser:
    """Outward compatibility facade for Check Point R80/R81 configuration parsing."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_content = content
        self.zone_mapping = zone_mapping or {}

    def parse(self) -> IRConfig:
        extraction = extract_checkpoint_config(self.raw_content, zone_mapping=self.zone_mapping)
        return extraction.canonical_ir
