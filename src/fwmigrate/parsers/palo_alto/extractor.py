"""Stable PAN-OS extraction entry points."""

from __future__ import annotations

from typing import Dict, Optional

from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.extraction.models import ExtractionResult

from .pipeline import PANOSExtractionPipeline


class PANOSSourceParser(BaseSourceParser):
    """Stable source-parser facade for the ordered PAN-OS extraction stage."""

    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks (PAN-OS / Panorama)"

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml", ".json", ".txt"]

    def extract(
        self,
        content: str,
        zone_mapping: Optional[Dict[str, str]] = None,
    ) -> ExtractionResult:
        return extract_panos_config(content, zone_mapping=zone_mapping)


def extract_panos_config(
    content: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    return PANOSExtractionPipeline().extract(content, zone_mapping=zone_mapping)


__all__ = ["PANOSSourceParser", "extract_panos_config"]
