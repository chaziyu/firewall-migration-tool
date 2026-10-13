"""Junos collected source sanitization."""

from .extraction import sanitize_junos_source_text


class JuniperCollectedSourceSanitizer:
    vendor_id = "juniper_srx"

    def sanitize(self, source_text: str) -> str:
        return sanitize_junos_source_text(source_text)
