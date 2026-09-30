"""Check Point collected bundle validation and sanitization."""

import json

from fwmigrate.extraction.sanitize import sanitize_source_attributes


class CheckPointCollectedSourceSanitizer:
    vendor_id = "checkpoint"

    def sanitize(self, source_text: str) -> str:
        data = json.loads(source_text)
        if not isinstance(data, dict):
            raise ValueError("The vendor source must be a JSON object.")
        if data.get("format") != "checkpoint-export-v1":
            raise ValueError("Unsupported vendor source format.")
        return json.dumps(sanitize_source_attributes(data))
