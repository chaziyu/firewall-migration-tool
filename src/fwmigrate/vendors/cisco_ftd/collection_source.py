"""Cisco FMC collected bundle validation and sanitization."""

import json

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from .fmc.fmc_adapter import FMC_BUNDLE_FORMAT


class CiscoFTDCollectedSourceSanitizer:
    vendor_id = "cisco_ftd"

    def sanitize(self, source_text: str) -> str:
        data = json.loads(source_text)
        if not isinstance(data, dict):
            raise ValueError("The vendor source must be a JSON object.")
        if data.get("format") != FMC_BUNDLE_FORMAT:
            raise ValueError("Unsupported vendor source format.")
        return json.dumps(sanitize_source_attributes(data))
