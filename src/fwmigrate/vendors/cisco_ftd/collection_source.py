"""Cisco FTD bundle and CLI source validation and sanitization."""

import json

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .fmc.fmc_adapter import FMC_BUNDLE_FORMAT
from .fdm.fdm_adapter import FDM_BUNDLE_FORMAT
from .cli.section_scanner import scan_cisco_ftd_sections


def _sanitize_text_values(value):
    if isinstance(value, dict):
        return {key: _sanitize_text_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_text_values(item) for item in value]
    return sanitize_raw_text(value) if isinstance(value, str) else value


class CiscoFTDCollectedSourceSanitizer:
    vendor_id = "cisco_ftd"

    def sanitize(self, source_text: str) -> str:
        text = source_text.lstrip("\ufeff \t\r\n")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            if text.startswith(("{", "[", '"')) or not any(
                section.path in {"interfaces", "routes", "management"}
                for section in scan_cisco_ftd_sections(text)
            ):
                raise ValueError("Unsupported or malformed Cisco FTD source.") from exc
            return sanitize_raw_text(source_text)
        if not isinstance(data, dict):
            raise ValueError("The vendor source must be a JSON object.")
        if data.get("format") not in {FMC_BUNDLE_FORMAT, FDM_BUNDLE_FORMAT}:
            raise ValueError("Unsupported vendor source format.")
        return json.dumps(_sanitize_text_values(sanitize_source_attributes(data)))
