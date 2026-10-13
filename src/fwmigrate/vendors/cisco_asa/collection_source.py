"""Cisco ASA collected source sanitization."""

from fwmigrate.extraction.sanitize import sanitize_raw_text


class CiscoASACollectedSourceSanitizer:
    vendor_id = "cisco_asa"

    def sanitize(self, source_text: str) -> str:
        return sanitize_raw_text(source_text)
